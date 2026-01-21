#!/usr/bin/env python3
"""
Claude Code PreToolUse Hook: Compositional Bash Command Approval

This hook auto-approves Bash commands by reading your existing approved patterns
from Claude settings and applying compositional matching with safe wrappers.

EXAMPLE
-------
If you've approved "Bash(cargo test:*)", this hook will also approve:
    - "timeout 60 cargo test"
    - "RUST_BACKTRACE=1 cargo test --package foo"
    - "env FOO=bar cargo test"

SETTINGS LOCATIONS
------------------
Reads permissions from (in order):
    1. ~/.claude/settings.json
    2. $CLAUDE_PROJECT_DIR/.claude/settings.json
    3. $CLAUDE_PROJECT_DIR/.claude/settings.local.json

WRAPPERS
--------
These prefixes are stripped before matching against your approved patterns:
    - timeout N
    - nice [-n N]
    - env
    - ENV_VAR=value prefixes
    - .venv/bin/ paths

CHAINED COMMANDS
----------------
Commands with &&, ||, ;, | are split and ALL segments must be safe.
Command substitution ($(...) and backticks) is always rejected.

DEBUG
-----
    echo '{"tool_name": "Bash", "tool_input": {"command": "timeout 30 cargo test"}}' | python3 ~/.claude/hooks/claude-approve-hook.py
"""
import json
import sys
import re
import os
from pathlib import Path

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

tool_name = data.get("tool_name")
tool_input = data.get("tool_input", {})

if tool_name != "Bash":
    sys.exit(0)


def approve(reason):
    """Output approval JSON and exit."""
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason
        }
    }
    print(json.dumps(result))
    sys.exit(0)


def load_bash_patterns_from_file(filepath):
    """Load Bash(...) patterns from a Claude settings file."""
    patterns = []
    try:
        with open(filepath) as f:
            settings = json.load(f)
        permissions = settings.get("permissions", {}).get("allow", [])
        for perm in permissions:
            if perm.startswith("Bash(") and perm.endswith(")"):
                inner = perm[5:-1]  # Strip "Bash(" and ")"
                patterns.append(inner)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    return patterns


def load_all_bash_patterns():
    """Load Bash patterns from all Claude settings locations."""
    patterns = []

    # 1. User settings
    user_settings = Path.home() / ".claude" / "settings.json"
    patterns.extend(load_bash_patterns_from_file(user_settings))

    # 2. Project settings (if CLAUDE_PROJECT_DIR is set)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_settings = Path(project_dir) / ".claude" / "settings.json"
        patterns.extend(load_bash_patterns_from_file(project_settings))

        project_local = Path(project_dir) / ".claude" / "settings.local.json"
        patterns.extend(load_bash_patterns_from_file(project_local))

    return patterns


def pattern_matches(cmd, pattern):
    """Check if command matches a Bash permission pattern.

    Pattern formats:
        "git diff:*"     -> matches "git diff" followed by anything
        "git diff"       -> matches exactly "git diff" (or as prefix)
        "RUST_LOG=debug cargo test:*" -> matches that exact prefix
    """
    if pattern.endswith(":*"):
        # Wildcard pattern: command must start with the prefix
        prefix = pattern[:-2]  # Remove ":*"
        return cmd == prefix or cmd.startswith(prefix + " ") or cmd.startswith(prefix)
    else:
        # Exact match or prefix match
        return cmd == pattern or cmd.startswith(pattern + " ") or cmd.startswith(pattern)


cmd = tool_input.get("command", "")


def has_dangerous_constructs(cmd):
    """Check for command substitution outside of quoted strings.

    $(...) and backticks are dangerous when they're actual command substitution,
    but harmless when they're literal characters inside quotes (e.g., markdown
    in commit messages).
    """
    # Remove quoted strings to check what's left
    # Use a simple state machine to handle nested quotes properly
    unquoted = []
    i = 0
    while i < len(cmd):
        if cmd[i] == '"':
            # Skip double-quoted string
            i += 1
            while i < len(cmd) and cmd[i] != '"':
                if cmd[i] == '\\' and i + 1 < len(cmd):
                    i += 2  # Skip escaped char
                else:
                    i += 1
            i += 1  # Skip closing quote
        elif cmd[i] == "'":
            # Skip single-quoted string (no escapes in single quotes)
            i += 1
            while i < len(cmd) and cmd[i] != "'":
                i += 1
            i += 1  # Skip closing quote
        else:
            unquoted.append(cmd[i])
            i += 1

    unquoted_str = "".join(unquoted)
    return bool(re.search(r"\$\(|`", unquoted_str))


# --- Reject dangerous constructs that are hard to parse safely ---
if has_dangerous_constructs(cmd):
    sys.exit(0)


def split_command_chain(cmd):
    """Split command into segments on &&, ||, ;, |."""
    # Collapse backslash-newline continuations
    cmd = re.sub(r"\\\n\s*", " ", cmd)

    # Protect quoted strings from splitting
    quoted_strings = []
    def save_quoted(m):
        quoted_strings.append(m.group(0))
        return f"__QUOTED_{len(quoted_strings)-1}__"
    cmd = re.sub(r'"[^"]*"', save_quoted, cmd)
    cmd = re.sub(r"'[^']*'", save_quoted, cmd)

    # Normalize redirections to prevent splitting on & in 2>&1
    cmd = re.sub(r"(\d*)>&(\d*)", r"__REDIR_\1_\2__", cmd)
    cmd = re.sub(r"&>", "__REDIR_AMPGT__", cmd)

    # Split on command separators
    if quoted_strings:
        segments = re.split(r"\s*(?:&&|\|\||;|\||&)\s*", cmd)
    else:
        segments = re.split(r"\s*(?:&&|\|\||;|\||&)\s*|\n", cmd)

    # Restore quoted strings and redirections
    def restore(s):
        s = re.sub(r"__REDIR_(\d*)_(\d*)__", r"\1>&\2", s)
        s = s.replace("__REDIR_AMPGT__", "&>")
        for i, qs in enumerate(quoted_strings):
            s = s.replace(f"__QUOTED_{i}__", qs)
        return s
    segments = [restore(s) for s in segments]
    return [s.strip() for s in segments if s.strip()]


# --- Safe wrappers that can prefix any approved command ---
WRAPPER_PATTERNS = [
    (r"^timeout\s+\d+\s+", "timeout"),
    (r"^nice\s+(-n\s*\d+\s+)?", "nice"),
    (r"^env\s+", "env"),
    (r"^([A-Z_][A-Z0-9_]*=[^\s]*\s+)+", "env vars"),
    # Virtual env paths
    (r"^(\.\./)*\.?venv/bin/", ".venv"),
    (r"^/[^\s]+/\.?venv/bin/", ".venv"),
    # do (loop body prefix)
    (r"^do\s+", "do"),
]


def strip_wrappers(cmd):
    """Strip safe wrapper prefixes, return (core_cmd, list_of_wrappers)."""
    wrappers = []
    changed = True
    while changed:
        changed = False
        for pattern, name in WRAPPER_PATTERNS:
            m = re.match(pattern, cmd)
            if m:
                wrappers.append(name)
                cmd = cmd[m.end():]
                changed = True
                break
    return cmd.strip(), wrappers


def check_against_patterns(cmd, patterns):
    """Check if command matches any approved pattern. Returns pattern or None."""
    for pattern in patterns:
        if pattern_matches(cmd, pattern):
            return pattern
    return None


# --- Main logic ---
patterns = load_all_bash_patterns()

if not patterns:
    # No patterns loaded, fall through to default approval
    sys.exit(0)

segments = split_command_chain(cmd)
reasons = []

for segment in segments:
    # First try matching the full segment (handles pre-approved exact commands)
    matched = check_against_patterns(segment, patterns)
    if matched:
        reasons.append(f"approved:{matched}")
        continue

    # Try stripping wrappers and matching the core command
    core_cmd, wrappers = strip_wrappers(segment)
    matched = check_against_patterns(core_cmd, patterns)

    if not matched:
        # One unmatched segment = reject entire command
        sys.exit(0)

    if wrappers:
        reasons.append(f"{'+'.join(wrappers)} + {matched}")
    else:
        reasons.append(matched)

approve(" | ".join(reasons))
