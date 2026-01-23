#!/usr/bin/env python3
"""
Tests for claude-approve-hook.py

Run with: python3 test_claude_approve_hook.py
"""
import subprocess
import json
import sys
from pathlib import Path

HOOK_PATH = Path(__file__).parent / "claude-approve-hook.py"

# =============================================================================
# TEST CASES
# =============================================================================
# Each test case is: (patterns, command, should_allow, description)
#
# patterns:      List of approved Bash patterns (like in settings.json)
# command:       The bash command being tested
# should_allow:  True if the hook should approve, False if it should reject
# description:   Human-readable description of what's being tested
# =============================================================================

TEST_CASES = [
    # -------------------------------------------------------------------------
    # Basic pattern matching
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "cargo test",
        True,
        "Exact match with wildcard pattern",
    ),
    (
        ["cargo test:*"],
        "cargo test --package foo",
        True,
        "Wildcard pattern matches with arguments",
    ),
    (
        ["cargo test:*"],
        "cargo build",
        False,
        "Different command not matched",
    ),
    (
        ["git log:*", "git diff:*"],
        "git log --oneline",
        True,
        "Multiple patterns - first matches",
    ),
    (
        ["git log:*", "git diff:*"],
        "git diff HEAD",
        True,
        "Multiple patterns - second matches",
    ),
    (
        ["git log:*", "git diff:*"],
        "git push",
        False,
        "Multiple patterns - none match",
    ),

    # -------------------------------------------------------------------------
    # Wrapper stripping: timeout
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "timeout 30 cargo test",
        True,
        "timeout wrapper is stripped",
    ),
    (
        ["cargo test:*"],
        "timeout 120 cargo test --package foo",
        True,
        "timeout with different value still works",
    ),
    (
        ["pytest:*"],
        "timeout 60 pytest tests/",
        True,
        "timeout works with other commands too",
    ),

    # -------------------------------------------------------------------------
    # Wrapper stripping: environment variables
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "RUST_BACKTRACE=1 cargo test",
        True,
        "Single env var prefix is stripped",
    ),
    (
        ["cargo test:*"],
        "RUST_BACKTRACE=1 RUST_LOG=debug cargo test",
        True,
        "Multiple env vars are stripped",
    ),
    (
        ["cargo test:*"],
        "FOO=bar BAZ=qux cargo test --package x",
        True,
        "Arbitrary env vars work",
    ),

    # -------------------------------------------------------------------------
    # Wrapper stripping: combined wrappers
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "timeout 60 RUST_BACKTRACE=1 cargo test",
        True,
        "timeout + env vars combined",
    ),
    (
        ["cargo test:*"],
        "RUST_LOG=debug timeout 30 cargo test",
        True,
        "env vars before timeout - wrapper order doesn't matter",
    ),
    (
        ["pytest:*"],
        "timeout 120 PYTHONPATH=/app pytest -v",
        True,
        "timeout + env var with path value",
    ),

    # -------------------------------------------------------------------------
    # Wrapper stripping: nice
    # -------------------------------------------------------------------------
    (
        ["cargo build:*"],
        "nice cargo build",
        True,
        "nice wrapper without priority",
    ),
    (
        ["cargo build:*"],
        "nice -n 10 cargo build",
        True,
        "nice wrapper with priority",
    ),

    # -------------------------------------------------------------------------
    # Wrapper stripping: env command
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "env cargo test",
        True,
        "env command prefix",
    ),
    (
        ["python:*"],
        "env FOO=bar python script.py",
        True,
        "env command + env vars both stripped",
    ),

    # -------------------------------------------------------------------------
    # Chained commands: all must match
    # -------------------------------------------------------------------------
    (
        ["git add:*", "git commit:*"],
        "git add . && git commit -m 'test'",
        True,
        "Chained commands - both match",
    ),
    (
        ["git add:*"],
        "git add . && git commit -m 'test'",
        False,
        "Chained commands - second doesn't match",
    ),
    (
        ["cargo fmt:*", "cargo test:*"],
        "cargo fmt && cargo test",
        True,
        "Two cargo commands chained",
    ),
    (
        ["ls:*", "cat:*"],
        "ls -la | cat",
        True,
        "Pipe - both sides match",
    ),
    (
        ["git status:*", "git diff:*"],
        "git status; git diff",
        True,
        "Semicolon separator",
    ),
    (
        ["cargo test:*"],
        "cargo test || true",
        False,
        "|| with unmatched 'true'",
    ),

    # -------------------------------------------------------------------------
    # Dangerous constructs - always rejected
    # -------------------------------------------------------------------------
    (
        ["rm:*"],
        "rm $(find . -name '*.tmp')",
        False,
        "Command substitution $() is rejected even with matching pattern",
    ),
    (
        ["rm:*"],
        "rm `find . -name '*.tmp'`",
        False,
        "Backtick substitution is rejected even with matching pattern",
    ),

    # -------------------------------------------------------------------------
    # Exact patterns (no :* wildcard)
    # -------------------------------------------------------------------------
    (
        ["cargo test"],
        "cargo test",
        True,
        "Exact pattern matches exactly",
    ),
    (
        ["cargo test"],
        "cargo test --package foo",
        True,
        "Exact pattern also works as prefix",
    ),
    (
        ["RUST_LOG=debug cargo test:*"],
        "RUST_LOG=debug cargo test",
        True,
        "Pattern with env var - exact match",
    ),
    (
        ["RUST_LOG=debug cargo test:*"],
        "cargo test",
        False,
        "Pattern with env var - plain command doesn't match",
    ),

    # -------------------------------------------------------------------------
    # Glob patterns in command prefix
    # -------------------------------------------------------------------------
    (
        ["cd ~/figma-worktrees*:*"],
        "cd ~/figma-worktrees/pr-659566-refactor-restore-httpproxy",
        True,
        "Glob * matches path components after prefix",
    ),
    (
        ["cd ~/figma-worktrees*:*"],
        "cd ~/figma-worktrees/some/deep/nested/path",
        True,
        "Glob * matches multiple path components",
    ),
    (
        ["cd ~/figma-worktrees*:*"],
        "cd ~/other-directory",
        False,
        "Glob * doesn't match completely different path",
    ),
    (
        ["ls /tmp/*:*"],
        "ls /tmp/foo",
        True,
        "Glob * at end of path matches filename",
    ),
    (
        ["ls /tmp/*:*"],
        "ls /tmp/foo/bar",
        True,
        "Glob * matches subdirectories too",
    ),
    (
        ["cat /home/*/file.txt:*"],
        "cat /home/alice/file.txt",
        True,
        "Glob * in middle of path matches single component",
    ),
    (
        ["cat /home/*/file.txt:*"],
        "cat /home/bob/file.txt",
        True,
        "Glob * in middle matches different usernames",
    ),
    (
        ["ls file?.txt:*"],
        "ls file1.txt",
        True,
        "Glob ? matches single character",
    ),
    (
        ["ls file?.txt:*"],
        "ls fileA.txt",
        True,
        "Glob ? matches single letter",
    ),
    (
        ["ls file?.txt:*"],
        "ls file10.txt",
        False,
        "Glob ? does not match multiple characters",
    ),
    (
        ["cd ~/worktrees*:*", "bazel query:*"],
        "cd ~/worktrees/pr-123 && bazel query //...",
        True,
        "Glob pattern in chained command - both match",
    ),
    (
        ["rm /tmp/test-*:*"],
        "rm /tmp/test-output.log",
        True,
        "Glob * for temp file cleanup pattern",
    ),
    (
        ["rm /tmp/test-*:*"],
        "rm /tmp/important.log",
        False,
        "Glob * doesn't match without prefix",
    ),

    # -------------------------------------------------------------------------
    # Edge cases
    # -------------------------------------------------------------------------
    (
        ["cargo test:*"],
        "cargo",
        False,
        "Partial command doesn't match",
    ),
    (
        ["cargo:*"],
        "cargo test",
        True,
        "Short pattern matches longer command",
    ),
    (
        [],
        "cargo test",
        False,
        "Empty patterns - nothing matches (falls through)",
    ),
    (
        ["git diff:*"],
        "git diff HEAD -- 'file with spaces.txt'",
        True,
        "Quoted arguments are preserved",
    ),

    # -------------------------------------------------------------------------
    # Multiline strings (commit messages, etc.)
    # -------------------------------------------------------------------------
    (
        ["git add:*", "git commit:*"],
        '''git add -A && git commit -m "fix: use correct colon wildcard syntax

Pattern syntax uses `:*` not ` *` for wildcards.
`git show:*` matches 'git show' followed by anything."''',
        True,
        "Multiline commit message with && should not split inside quotes",
    ),
    (
        ["git commit:*"],
        '''git commit -m "line1
line2
line3"''',
        True,
        "Simple multiline commit message",
    ),
    (
        ["echo:*", "git status:*"],
        'echo "foo && bar" && git status',
        True,
        "&& inside quotes should not cause split",
    ),
    (
        ["git commit:*"],
        '''git commit -m "fix: handle edge case

- Added new test
- Updated docs
- Fixed bug where | would break things"''',
        True,
        "Multiline with pipe character inside quotes",
    ),
    (
        ["git add:*", "git commit:*"],
        '''git add -A && git commit -m "feat: add new feature

This is a longer description that spans
multiple lines and contains special chars like:
- bullets
- `code`
- colons: like this"''',
        True,
        "Complex multiline commit with special characters",
    ),
    (
        ["git commit:*"],
        'git commit -m "test; with semicolon"',
        True,
        "Semicolon inside quotes should not split",
    ),
    (
        ["git add:*"],
        "git add -A && git commit -m 'unmatched'",
        False,
        "Multiline-adjacent: second command unmatched should fail",
    ),
    # -------------------------------------------------------------------------
    # Escaped semicolons and redirections
    # -------------------------------------------------------------------------
    (
        ["find:*"],
        r'find . -name "*.tmp" -exec rm {} \;',
        True,
        "Escaped semicolon in find -exec should not split command",
    ),
    (
        ["find:*", "true:*"],
        r'find . -name "*.tmp" -exec rm {} \; 2>/dev/null || true',
        True,
        "2>/dev/null redirection should be filtered out, not treated as segment",
    ),
    (
        ["mkdir:*", "find:*", "true:*"],
        r'mkdir -p ~/tmp && find ~/tmp -name "pr-*" -exec rm {} \; 2>/dev/null || true',
        True,
        "Complex command with escaped semicolon, redirection, and || true",
    ),
    (
        ["cat:*"],
        "cat file.txt 2>/dev/null",
        True,
        "Simple redirection stays attached to command",
    ),
    (
        ["ls:*", "grep:*"],
        "ls -la 2>&1 | grep foo",
        True,
        "2>&1 redirection should not cause issues",
    ),
]


def run_hook(patterns: list[str], command: str) -> bool:
    """Run the hook with given patterns and command, return True if approved."""
    import tempfile
    import os

    # Create a temporary settings file with the patterns
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create fake home dir with .claude/settings.json
        fake_home = Path(tmpdir) / "home"
        fake_home.mkdir()
        settings_dir = fake_home / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.json"

        permissions = [f"Bash({p})" for p in patterns]
        settings_file.write_text(json.dumps({
            "permissions": {"allow": permissions}
        }))

        # Run the hook
        input_data = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command}
        })

        env = os.environ.copy()
        # Override HOME to isolate from user's global settings
        env["HOME"] = str(fake_home)
        env["CLAUDE_PROJECT_DIR"] = tmpdir

        result = subprocess.run(
            ["python3", str(HOOK_PATH)],
            input=input_data,
            capture_output=True,
            text=True,
            env=env,
        )

        # If hook outputs JSON with "allow", it's approved
        if result.stdout.strip():
            try:
                output = json.loads(result.stdout)
                decision = output.get("hookSpecificOutput", {}).get("permissionDecision")
                return decision == "allow"
            except json.JSONDecodeError:
                pass

        return False


def main():
    print("=" * 70)
    print("CLAUDE-APPROVE-HOOK TESTS")
    print("=" * 70)
    print()

    passed = 0
    failed = 0
    failures = []

    for patterns, command, should_allow, description in TEST_CASES:
        actual = run_hook(patterns, command)
        success = actual == should_allow

        if success:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
            failures.append((patterns, command, should_allow, actual, description))

        expected_str = "ALLOW" if should_allow else "DENY"
        print(f"{status}  {description}")
        print(f"       Patterns: {patterns}")
        print(f"       Command:  {command}")
        print(f"       Expected: {expected_str}")
        if not success:
            actual_str = "ALLOW" if actual else "DENY"
            print(f"       Actual:   {actual_str}")
        print()

    print("=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)

    if failures:
        print("\nFAILURES:")
        for patterns, command, should_allow, actual, description in failures:
            expected_str = "ALLOW" if should_allow else "DENY"
            actual_str = "ALLOW" if actual else "DENY"
            print(f"\n  {description}")
            print(f"    Patterns: {patterns}")
            print(f"    Command:  {command}")
            print(f"    Expected: {expected_str}, Got: {actual_str}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
