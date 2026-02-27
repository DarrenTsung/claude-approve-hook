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

COMMAND FEEDBACK
----------------
You can configure feedback rules to block commands and suggest alternatives.
Create a command-feedback.json file:
    - ~/.claude/command-feedback.json (global)
    - $CLAUDE_PROJECT_DIR/.claude/command-feedback.json (project)

Example command-feedback.json:
    [
      {
        "match": "bazel test //multiplayer:test.*--test_arg=",
        "message": "Use --test_filter instead of --test_arg.",
        "suggest": "bazel test //multiplayer:test --test_filter=\"$TEST_PATTERN\""
      }
    ]

Fields:
    - match: Regex pattern to match commands
    - message: Feedback shown to Claude when blocked
    - suggest: (optional) Suggested command, supports {1}, {2} for capture groups

COMMENTS
--------
Comment-only lines (starting with #) are stripped before matching. Claude often
prefixes commands with a comment explaining intent, e.g.:
    # Check pod counts for render workers
    datadog metrics query --query '...'

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

COMMAND SUBSTITUTION
--------------------
$(...) substitutions are recursively checked (1 level deep): if every inner
command matches an approved pattern, the substitution is allowed and the outer
command is checked normally. Nested $(...) (more than 1 level) is rejected.
Backtick substitution is always rejected (use $() syntax instead).

DEBUG
-----
    echo '{"tool_name": "Bash", "tool_input": {"command": "timeout 30 cargo test"}}' | python3 ~/.claude/hooks/claude-approve-hook.py

CLI MODES
---------
Test mode (debug why a command wasn't approved):
    python3 claude-approve-hook.py --test "cargo test --package foo"
    python3 claude-approve-hook.py --test "cargo test" --cwd /path/to/project
"""
import json
import sys
import re
import os
import argparse
import fnmatch
from datetime import datetime
from pathlib import Path


LOG_FILE = Path.home() / ".claude" / "hooks" / "approval.log"


def parse_cli_args():
    """Parse command-line arguments for test/add modes."""
    parser = argparse.ArgumentParser(
        description="Claude Code Bash command approval hook",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--test", "-t",
        metavar="COMMAND",
        help="Test a command and show debug info on approval decision"
    )
    parser.add_argument(
        "--cwd", "-c",
        metavar="DIR",
        help="Working directory context (sets CLAUDE_PROJECT_DIR for pattern loading)"
    )
    return parser.parse_args()


# Check for CLI mode before reading stdin
args = parse_cli_args()

if args.test:
    # Handle --test mode (defined later, after helper functions)
    pass
elif sys.stdin.isatty():
    # No stdin and no flags - show help
    print("Usage: claude-approve-hook.py [--test COMMAND] [--add PATTERN]", file=sys.stderr)
    print("       Or pipe JSON from Claude Code hook system", file=sys.stderr)
    sys.exit(0)
else:
    # Normal hook mode - read from stdin
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input", {})

    if tool_name != "Bash":
        sys.exit(0)

    cmd = tool_input.get("command", "")


def log_decision(command, decision, reason):
    """Append a decision record to the log file."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now().astimezone().isoformat(),
            "cwd": os.environ.get("CLAUDE_PROJECT_DIR", ""),
            "command": command,
            "decision": decision,
            "reason": reason,
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # Don't fail the hook if logging fails


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


def deny(reason):
    """Output denial JSON and exit."""
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    }
    print(json.dumps(result))
    sys.exit(0)


def check_feedback_rules(cmd, rules):
    """Check if command matches any feedback rule. Returns (rule, match) or (None, None)."""
    for rule in rules:
        pattern = rule.get("match", "")
        try:
            match = re.search(pattern, cmd)
            if match:
                return rule, match
        except re.error:
            # Invalid regex, skip this rule
            continue
    return None, None


def format_feedback_message(rule, cmd, match):
    """Format the feedback message, substituting capture groups in 'suggest'."""
    message = rule.get("message", "")

    suggest = rule.get("suggest")
    if suggest:
        # Substitute capture groups: {1}, {2}, etc.
        for i, group in enumerate(match.groups(), 1):
            if group is not None:
                suggest = suggest.replace(f"{{{i}}}", group)
        message = f"{message}\n\nSuggested: {suggest}"

    return message


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


def load_feedback_rules_from_file(filepath):
    """Load commandFeedback rules from a dedicated feedback config file.

    Expected format:
    {
      "rules": [
        {"match": "...", "message": "...", "suggest": "..."}
      ]
    }

    Or just a bare array:
    [
      {"match": "...", "message": "...", "suggest": "..."}
    ]
    """
    rules = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        # Support both {"rules": [...]} and bare [...]
        if isinstance(data, list):
            feedback = data
        else:
            feedback = data.get("rules", [])
        for rule in feedback:
            if "match" in rule and "message" in rule:
                rules.append(rule)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    return rules


def load_all_feedback_rules():
    """Load feedback rules from command-feedback.json files.

    Reads from:
      1. ~/.claude/command-feedback.json
      2. $CLAUDE_PROJECT_DIR/.claude/command-feedback.json
    """
    rules = []

    # 1. User feedback config
    user_feedback = Path.home() / ".claude" / "command-feedback.json"
    rules.extend(load_feedback_rules_from_file(user_feedback))

    # 2. Project feedback config (if CLAUDE_PROJECT_DIR is set)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_feedback = Path(project_dir) / ".claude" / "command-feedback.json"
        rules.extend(load_feedback_rules_from_file(project_feedback))

    return rules


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


def has_glob_chars(s):
    """Check if string contains glob wildcard characters."""
    return any(c in s for c in '*?[')


def pattern_matches(cmd, pattern):
    """Check if command matches a Bash permission pattern.

    Pattern formats:
        "git diff:*"     -> matches "git diff" followed by anything
        "git diff"       -> matches exactly "git diff" (or as prefix)
        "RUST_LOG=debug cargo test:*" -> matches that exact prefix
        "cd ~/worktrees*:*" -> glob pattern, * matches any chars including /
    """
    if pattern.endswith(":*"):
        # Wildcard pattern: command must start with the prefix
        prefix = pattern[:-2]  # Remove ":*"

        # Check if prefix contains glob characters
        if has_glob_chars(prefix):
            # Use fnmatch for glob matching
            # Try exact match first, then with additional args
            if fnmatch.fnmatch(cmd, prefix):
                return True
            if fnmatch.fnmatch(cmd, prefix + " *"):
                return True
            return False
        else:
            # Original behavior: simple prefix matching
            return cmd == prefix or cmd.startswith(prefix + " ") or cmd.startswith(prefix)
    else:
        # Exact match or prefix match
        if has_glob_chars(pattern):
            # Use fnmatch for glob matching
            if fnmatch.fnmatch(cmd, pattern):
                return True
            if fnmatch.fnmatch(cmd, pattern + " *"):
                return True
            return False
        else:
            return cmd == pattern or cmd.startswith(pattern + " ") or cmd.startswith(pattern)


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


def extract_command_substitutions(cmd):
    """Extract $(...) command substitutions from unquoted portions of a command.

    Returns a list of (start, end, inner_cmd) tuples for each $(...) found,
    or None if backticks are found (unsupported for recursive checking).

    Only handles one level of $(...) — nested $(...) inside the inner command
    is detected and rejected separately.
    """
    results = []
    i = 0
    while i < len(cmd):
        if cmd[i] == '"':
            # Skip double-quoted string
            i += 1
            while i < len(cmd) and cmd[i] != '"':
                if cmd[i] == '\\' and i + 1 < len(cmd):
                    i += 2
                else:
                    i += 1
            i += 1  # Skip closing quote
        elif cmd[i] == "'":
            # Skip single-quoted string
            i += 1
            while i < len(cmd) and cmd[i] != "'":
                i += 1
            i += 1  # Skip closing quote
        elif cmd[i] == '`':
            # Backtick found outside quotes — not supported
            return None
        elif cmd[i] == '$' and i + 1 < len(cmd) and cmd[i + 1] == '(':
            # Found $( — find matching ) tracking paren depth
            start = i
            i += 2  # Skip $(
            depth = 1
            inner_start = i
            while i < len(cmd) and depth > 0:
                if cmd[i] == '(':
                    depth += 1
                elif cmd[i] == ')':
                    depth -= 1
                elif cmd[i] == '"':
                    # Skip double-quoted string inside substitution
                    i += 1
                    while i < len(cmd) and cmd[i] != '"':
                        if cmd[i] == '\\' and i + 1 < len(cmd):
                            i += 2
                        else:
                            i += 1
                elif cmd[i] == "'":
                    # Skip single-quoted string inside substitution
                    i += 1
                    while i < len(cmd) and cmd[i] != "'":
                        i += 1
                i += 1
            if depth == 0:
                inner_cmd = cmd[inner_start:i - 1]  # Exclude closing )
                results.append((start, i, inner_cmd))
            # If depth != 0, unmatched parens — skip (will fail elsewhere)
        else:
            i += 1
    return results


def replace_substitutions_with_placeholder(cmd, substitutions):
    """Replace $(…) substitutions with a safe placeholder string.

    Substitutions must be in order of appearance. Replaces right-to-left
    to preserve offsets.
    """
    result = cmd
    for start, end, _ in reversed(substitutions):
        result = result[:start] + "__CMD_SUB__" + result[end:]
    return result


def analyze_inner_command(inner_cmd, patterns):
    """Analyze an inner command (from $(...)) against patterns.

    Reuses segment analysis logic from analyze_command but without recursive
    substitution checking (enforcing 1-level depth).

    Returns dict with:
        - approved: bool
        - reason: str
        - segments: list of segment analysis dicts
    """
    result = {
        "approved": False,
        "reason": "",
        "segments": [],
        "inner_cmd": inner_cmd,
    }

    segments = split_command_chain(inner_cmd)
    reasons = []
    all_matched = True
    first_unmatched_core = None

    for segment in segments:
        seg_analysis = {
            "segment": segment,
            "matched": False,
            "matched_pattern": None,
            "wrappers": [],
            "core_cmd": segment,
        }

        # Try full segment first
        matched = check_against_patterns(segment, patterns)
        if matched:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = matched
            reasons.append(f"approved:{matched}")
            result["segments"].append(seg_analysis)
            continue

        # Try stripping wrappers
        core_cmd, wrappers = strip_wrappers(segment)
        seg_analysis["core_cmd"] = core_cmd
        seg_analysis["wrappers"] = wrappers

        # Standalone variable assignment (e.g., FOO=$(cmd)) — after stripping
        # env var wrappers, nothing remains. Safe if the substitution was approved.
        if not core_cmd and "env vars" in wrappers:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = "(assignment)"
            reasons.append("assignment")
            result["segments"].append(seg_analysis)
            continue

        matched = check_against_patterns(core_cmd, patterns)
        if matched:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = matched
            if wrappers:
                reasons.append(f"{'+'.join(wrappers)} + {matched}")
            else:
                reasons.append(matched)
        else:
            all_matched = False
            if first_unmatched_core is None:
                first_unmatched_core = core_cmd

        result["segments"].append(seg_analysis)

    if all_matched:
        result["approved"] = True
        result["reason"] = " | ".join(reasons)
    else:
        result["reason"] = f"No matching pattern for: {first_unmatched_core}"

    return result


def split_command_chain(cmd):
    """Split command into segments on &&, ||, ;, |."""
    # Collapse backslash-newline continuations
    cmd = re.sub(r"\\\n\s*", " ", cmd)

    # Strip comment-only lines (e.g., "# description of what this does")
    # Claude often prefixes commands with a comment explaining the intent.
    lines = cmd.split('\n')
    lines = [l for l in lines if not l.strip().startswith('#')]
    cmd = '\n'.join(lines)

    # Protect quoted strings from splitting
    # For double quotes: handle escaped characters (e.g., \" inside the string)
    # For single quotes: no escape sequences in bash, so simple [^']* works
    quoted_strings = []
    def save_quoted(m):
        quoted_strings.append(m.group(0))
        return f"__QUOTED_{len(quoted_strings)-1}__"
    # Single pass: match single-quoted OR double-quoted strings together.
    # This prevents " inside '...' from being misinterpreted as a real
    # double-quote delimiter (and vice versa).
    cmd = re.sub(r"'[^']*'" r'|"(?:[^"\\]|\\.)*"', save_quoted, cmd)

    # Protect escaped semicolons (e.g., find -exec ... \;)
    cmd = cmd.replace("\\;", "__ESCAPED_SEMI__")

    # Normalize redirections to prevent splitting on & in 2>&1
    cmd = re.sub(r"(\d*)>&(\d*)", r"__REDIR_\1_\2__", cmd)
    cmd = re.sub(r"&>", "__REDIR_AMPGT__", cmd)

    # Split on command separators (but not standalone redirections)
    # Match && || ; | but not when preceded by digits (redirections like 2>)
    if quoted_strings:
        segments = re.split(r"\s*(?:&&|\|\||(?<!\d[<>]);|\|(?!\|)|(?<![<>])&(?!&))\s*", cmd)
    else:
        segments = re.split(r"\s*(?:&&|\|\||(?<!\d[<>]);|\|(?!\|)|(?<![<>])&(?!&))\s*|\n", cmd)

    # Restore quoted strings, escaped semicolons, and redirections
    def restore(s):
        s = re.sub(r"__REDIR_(\d*)_(\d*)__", r"\1>&\2", s)
        s = s.replace("__REDIR_AMPGT__", "&>")
        s = s.replace("__ESCAPED_SEMI__", "\\;")
        for i, qs in enumerate(quoted_strings):
            s = s.replace(f"__QUOTED_{i}__", qs)
        return s
    segments = [restore(s) for s in segments]

    # Filter out standalone redirections (e.g., "2>/dev/null") - these belong to previous command
    # but when split incorrectly, we should just ignore them as they're safe
    filtered = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        # Skip standalone redirections
        if re.match(r"^\d*[<>]", seg):
            continue
        filtered.append(seg)

    return filtered


def normalize_git_cwd(cmd, cwd=None):
    """Normalize 'git -C <path>' to 'git' when <path> matches the current directory.

    This allows patterns like 'git diff:*' to match 'git -C /current/dir diff'.
    """
    if not cmd.startswith("git -C "):
        return cmd

    if cwd is None:
        # Use CLAUDE_PROJECT_DIR if set (for testing), otherwise use actual cwd
        cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()

    # Normalize the reference directory
    cwd = os.path.realpath(cwd)

    # Parse: git -C <path> <rest>
    # The path could be quoted or unquoted
    rest = cmd[7:]  # After "git -C "

    if rest.startswith('"'):
        # Quoted path
        end_quote = rest.find('"', 1)
        if end_quote == -1:
            return cmd  # Malformed, don't modify
        path = rest[1:end_quote]
        after_path = rest[end_quote + 1:].lstrip()
    elif rest.startswith("'"):
        # Single-quoted path
        end_quote = rest.find("'", 1)
        if end_quote == -1:
            return cmd  # Malformed, don't modify
        path = rest[1:end_quote]
        after_path = rest[end_quote + 1:].lstrip()
    else:
        # Unquoted path - ends at first whitespace
        parts = rest.split(None, 1)
        if not parts:
            return cmd
        path = parts[0]
        after_path = parts[1] if len(parts) > 1 else ""

    # Normalize the path from the command
    try:
        cmd_path = os.path.realpath(os.path.expanduser(path))
    except (OSError, ValueError):
        return cmd

    # If the paths match, return git without -C
    if cmd_path == cwd:
        return f"git {after_path}".strip()

    return cmd


# --- Safe wrappers that can prefix any approved command ---
WRAPPER_PATTERNS = [
    (r"^time\s+", "time"),
    (r"^timeout\s+\d+\s+", "timeout"),
    (r"^nice\s+(-n\s*\d+\s+)?", "nice"),
    (r"^env\s+", "env"),
    (r"^([A-Z_][A-Z0-9_]*=[^\s]*(\s+|$))+", "env vars"),
    # Virtual env paths
    (r"^(\.\./)*\.?venv/bin/", ".venv"),
    (r"^/[^\s]+/\.?venv/bin/", ".venv"),
    # do (loop body prefix)
    (r"^do\s+", "do"),
]


def strip_wrappers(cmd, cwd=None):
    """Strip safe wrapper prefixes, return (core_cmd, list_of_wrappers).

    Also normalizes 'git -C <cwd>' to 'git' when the path matches the current directory.
    """
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

    cmd = cmd.strip()

    # Normalize git -C <cwd> to git
    normalized = normalize_git_cwd(cmd, cwd)
    if normalized != cmd:
        wrappers.append("git -C <cwd>")
        cmd = normalized

    return cmd, wrappers


def check_against_patterns(cmd, patterns):
    """Check if command matches any approved pattern. Returns pattern or None."""
    for pattern in patterns:
        if pattern_matches(cmd, pattern):
            return pattern
    return None


def load_patterns_with_sources():
    """Load Bash patterns from all Claude settings locations with their sources."""
    patterns_with_sources = []

    # 1. User settings
    user_settings = Path.home() / ".claude" / "settings.json"
    for p in load_bash_patterns_from_file(user_settings):
        patterns_with_sources.append((p, str(user_settings)))

    # 2. Project settings (if CLAUDE_PROJECT_DIR is set)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_settings = Path(project_dir) / ".claude" / "settings.json"
        for p in load_bash_patterns_from_file(project_settings):
            patterns_with_sources.append((p, str(project_settings)))

        project_local = Path(project_dir) / ".claude" / "settings.local.json"
        for p in load_bash_patterns_from_file(project_local):
            patterns_with_sources.append((p, str(project_local)))

    return patterns_with_sources


def analyze_command(cmd, patterns):
    """Analyze a command and return detailed results.

    Returns dict with:
        - approved: bool
        - reason: str (approval reason or rejection reason)
        - segments: list of segment analysis dicts
        - dangerous: bool (if has dangerous constructs)
        - suggested_pattern: str or None (pattern to add to allow this command)
    """
    result = {
        "approved": False,
        "reason": "",
        "segments": [],
        "dangerous": False,
        "suggested_pattern": None
    }

    # Check for command substitutions ($() and backticks)
    subs = extract_command_substitutions(cmd)
    if subs is None:
        # Backticks found — always reject
        result["dangerous"] = True
        result["reason"] = "Contains backtick command substitution (use $() syntax for auto-approval)"
        return result

    if subs:
        if not patterns:
            result["reason"] = "No patterns loaded from settings"
            return result

        # Has $() substitutions — check each inner command
        sub_details = []
        for start, end, inner_cmd in subs:
            # Enforce 1-level depth: inner commands must not contain substitutions
            if has_dangerous_constructs(inner_cmd):
                result["dangerous"] = True
                result["reason"] = f"Nested command substitution not supported: $({inner_cmd})"
                return result

            # Check inner command against patterns
            inner_result = analyze_inner_command(inner_cmd, patterns)
            sub_details.append(inner_result)

            if not inner_result["approved"]:
                result["dangerous"] = True
                result["reason"] = f"Command substitution not approved: $({inner_cmd})"
                return result

        # All substitutions approved — replace with placeholder and continue
        result["substitutions"] = sub_details
        cmd = replace_substitutions_with_placeholder(cmd, subs)

    if not patterns:
        result["reason"] = "No patterns loaded from settings"
        return result

    segments = split_command_chain(cmd)
    reasons = []
    all_matched = True
    first_unmatched_core = None

    for segment in segments:
        seg_analysis = {
            "segment": segment,
            "matched": False,
            "matched_pattern": None,
            "wrappers": [],
            "core_cmd": segment
        }

        # First try matching the full segment
        matched = check_against_patterns(segment, patterns)
        if matched:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = matched
            reasons.append(f"approved:{matched}")
            result["segments"].append(seg_analysis)
            continue

        # Try stripping wrappers and matching the core command
        core_cmd, wrappers = strip_wrappers(segment)
        seg_analysis["core_cmd"] = core_cmd
        seg_analysis["wrappers"] = wrappers

        # Standalone variable assignment (e.g., FOO=$(cmd)) — after stripping
        # env var wrappers, nothing remains. Safe if the substitution was approved.
        if not core_cmd and "env vars" in wrappers:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = "(assignment)"
            reasons.append("assignment")
            result["segments"].append(seg_analysis)
            continue

        matched = check_against_patterns(core_cmd, patterns)

        if matched:
            seg_analysis["matched"] = True
            seg_analysis["matched_pattern"] = matched
            if wrappers:
                reasons.append(f"{'+'.join(wrappers)} + {matched}")
            else:
                reasons.append(matched)
        else:
            all_matched = False
            if first_unmatched_core is None:
                first_unmatched_core = core_cmd

        result["segments"].append(seg_analysis)

    if all_matched:
        result["approved"] = True
        result["reason"] = " | ".join(reasons)
    else:
        result["reason"] = f"No matching pattern for: {first_unmatched_core}"
        # Suggest a pattern: use first word(s) as base command with :* wildcard
        if first_unmatched_core:
            # Extract base command (first 1-2 words typically)
            parts = first_unmatched_core.split()
            if parts:
                # For common patterns like "git status", "cargo test", use first two words
                if len(parts) >= 2 and parts[0] in ("git", "cargo", "npm", "yarn", "pnpm", "bazel", "make", "docker", "kubectl"):
                    result["suggested_pattern"] = f"{parts[0]} {parts[1]}:*"
                else:
                    result["suggested_pattern"] = f"{parts[0]}:*"

    return result


def load_feedback_rules_with_sources():
    """Load feedback rules from command-feedback.json files with their sources."""
    rules_with_sources = []

    # 1. User feedback config
    user_feedback = Path.home() / ".claude" / "command-feedback.json"
    for r in load_feedback_rules_from_file(user_feedback):
        rules_with_sources.append((r, str(user_feedback)))

    # 2. Project feedback config (if CLAUDE_PROJECT_DIR is set)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_feedback = Path(project_dir) / ".claude" / "command-feedback.json"
        for r in load_feedback_rules_from_file(project_feedback):
            rules_with_sources.append((r, str(project_feedback)))

    return rules_with_sources


def run_test_mode(cmd):
    """Run test mode: analyze command and print debug info."""
    patterns_with_sources = load_patterns_with_sources()
    patterns = [p for p, _ in patterns_with_sources]
    feedback_rules_with_sources = load_feedback_rules_with_sources()
    feedback_rules = [r for r, _ in feedback_rules_with_sources]

    print("=" * 60)
    print("COMMAND ANALYSIS")
    print("=" * 60)
    print(f"\nCommand: {cmd}\n")

    # Show loaded feedback rules
    print("-" * 40)
    print("FEEDBACK RULES")
    print("-" * 40)
    if feedback_rules_with_sources:
        for rule, source in feedback_rules_with_sources:
            short_source = source.replace(str(Path.home()), "~")
            print(f"  match: {rule.get('match')}  <- {short_source}")
            print(f"    message: {rule.get('message')}")
            if rule.get('suggest'):
                print(f"    suggest: {rule.get('suggest')}")
    else:
        print("  (no feedback rules found)")
    print()

    # Show loaded patterns
    print("-" * 40)
    print("LOADED PATTERNS")
    print("-" * 40)
    if patterns_with_sources:
        for pattern, source in patterns_with_sources:
            # Shorten path for display
            short_source = source.replace(str(Path.home()), "~")
            print(f"  Bash({pattern})  <- {short_source}")
    else:
        print("  (no patterns found)")
    print()

    # Check feedback rules first
    rule, match = check_feedback_rules(cmd, feedback_rules)
    if rule:
        print("-" * 40)
        print("FEEDBACK RULE MATCHED")
        print("-" * 40)
        print(f"\n  Rule: {rule.get('match')}")
        print(f"\n  Message to Claude:")
        message = format_feedback_message(rule, cmd, match)
        for line in message.split('\n'):
            print(f"    {line}")
        print()
        print("-" * 40)
        print("VERDICT")
        print("-" * 40)
        print(f"\n  DENIED (feedback rule): Command blocked with suggestion")
        print()
        return

    # Analyze
    result = analyze_command(cmd, patterns)

    # Show analysis
    print("-" * 40)
    print("ANALYSIS")
    print("-" * 40)

    if result["dangerous"]:
        print(f"\n  REJECTED: {result['reason']}")
        return

    # Show substitution analysis if present
    if result.get("substitutions"):
        print(f"\n  Command substitutions checked ({len(result['substitutions'])}):\n")
        for sub in result["substitutions"]:
            status = "APPROVED" if sub["approved"] else "REJECTED"
            print(f"    $({sub['inner_cmd']})  -> {status}: {sub['reason']}")
            for seg in sub.get("segments", []):
                if seg["wrappers"]:
                    print(f"      Wrappers: {', '.join(seg['wrappers'])}")
                if seg["matched"]:
                    print(f"      MATCHED: Bash({seg['matched_pattern']})")
        print()

    if len(result["segments"]) > 1:
        print(f"\n  Command chain split into {len(result['segments'])} segments:\n")

    for i, seg in enumerate(result["segments"], 1):
        if len(result["segments"]) > 1:
            print(f"  Segment {i}: {seg['segment']}")
        if seg["wrappers"]:
            print(f"    Wrappers stripped: {', '.join(seg['wrappers'])}")
            print(f"    Core command: {seg['core_cmd']}")
        if seg["matched"]:
            print(f"    MATCHED: Bash({seg['matched_pattern']})")
        else:
            print(f"    NOT MATCHED: {seg['core_cmd']}")
        print()

    # Final verdict
    print("-" * 40)
    print("VERDICT")
    print("-" * 40)
    if result["approved"]:
        print(f"\n  APPROVED: {result['reason']}")
    else:
        print(f"\n  NOT APPROVED: {result['reason']}")
        if result["suggested_pattern"]:
            print(f"\n  Suggested pattern to add:")
            print(f"    Bash({result['suggested_pattern']})")
            print(f"\n  To add this permission, run:")
            print(f"    python3 {sys.argv[0]} --add \"{result['suggested_pattern']}\"")
    print()


# --- Main execution ---
if args.test:
    # Set working directory context if provided
    if args.cwd:
        os.environ["CLAUDE_PROJECT_DIR"] = os.path.abspath(args.cwd)
    run_test_mode(args.test)
else:
    # Normal hook mode

    # Check feedback rules first (they take priority)
    feedback_rules = load_all_feedback_rules()
    if feedback_rules:
        rule, match = check_feedback_rules(cmd, feedback_rules)
        if rule:
            message = format_feedback_message(rule, cmd, match)
            log_decision(cmd, "denied", message)
            deny(message)

    # Then check approval patterns
    patterns = load_all_bash_patterns()

    if not patterns:
        log_decision(cmd, "no_patterns", "No patterns loaded from settings")
        sys.exit(0)

    result = analyze_command(cmd, patterns)

    if result["approved"]:
        approve(result["reason"])
    else:
        log_decision(cmd, "not_approved", result["reason"])
        sys.exit(0)
