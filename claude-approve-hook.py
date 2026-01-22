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
from pathlib import Path


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

    # Check for dangerous constructs
    if has_dangerous_constructs(cmd):
        result["dangerous"] = True
        result["reason"] = "Contains command substitution ($(...) or backticks) outside of quotes"
        return result

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


def run_test_mode(cmd):
    """Run test mode: analyze command and print debug info."""
    patterns_with_sources = load_patterns_with_sources()
    patterns = [p for p, _ in patterns_with_sources]

    print("=" * 60)
    print("COMMAND ANALYSIS")
    print("=" * 60)
    print(f"\nCommand: {cmd}\n")

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

    # Analyze
    result = analyze_command(cmd, patterns)

    # Show analysis
    print("-" * 40)
    print("ANALYSIS")
    print("-" * 40)

    if result["dangerous"]:
        print(f"\n  REJECTED: {result['reason']}")
        print("\n  Command substitution is never auto-approved for safety.")
        return

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
    patterns = load_all_bash_patterns()

    if not patterns:
        sys.exit(0)

    result = analyze_command(cmd, patterns)

    if result["approved"]:
        approve(result["reason"])
    else:
        sys.exit(0)
