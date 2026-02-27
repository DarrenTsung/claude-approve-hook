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

# =============================================================================
# FEEDBACK RULE TEST CASES
# =============================================================================
# Each test case is: (feedback_rules, patterns, command, expected_decision, expected_message_contains, description)
#
# feedback_rules: List of feedback rule dicts (match, message, suggest)
# patterns:       List of approved Bash patterns
# command:        The bash command being tested
# expected_decision: "allow", "deny", or None (falls through to user)
# expected_message_contains: String that should be in the denial reason (or None)
# description:    Human-readable description
# =============================================================================

FEEDBACK_TEST_CASES = [
    # -------------------------------------------------------------------------
    # Basic feedback rule matching
    # -------------------------------------------------------------------------
    (
        [{"match": r"bazel test.*--test_arg=", "message": "Use --test_filter instead of --test_arg"}],
        ["bazel test:*"],
        'bazel test //multiplayer:test --test_arg="foo"',
        "deny",
        "--test_filter",
        "Feedback rule blocks bazel test with --test_arg",
    ),
    (
        [{"match": r"bazel test.*--test_arg=", "message": "Use --test_filter instead of --test_arg"}],
        ["bazel test:*"],
        'bazel test //multiplayer:test --test_filter="foo"',
        "allow",
        None,
        "Command with --test_filter is allowed (no feedback rule match)",
    ),
    (
        [{"match": r"bazel test.*--test_arg=", "message": "Use --test_filter instead of --test_arg"}],
        [],
        'bazel test //multiplayer:test --test_arg="foo"',
        "deny",
        "--test_filter",
        "Feedback rule blocks even without approval patterns",
    ),
    # -------------------------------------------------------------------------
    # Feedback rules with capture groups in suggest
    # -------------------------------------------------------------------------
    (
        [{
            "match": r"bazel test (//\S+).*--test_arg=",
            "message": "Use --test_filter instead of --test_arg",
            "suggest": 'bazel test {1} --test_filter="$TEST_GLOB"'
        }],
        ["bazel test:*"],
        'bazel test //multiplayer:test --test_arg="foo"',
        "deny",
        "//multiplayer:test",
        "Capture group {1} substituted in suggestion",
    ),
    (
        [{
            "match": r"bazel test (//\S+).*--test_arg=",
            "message": "Use --test_filter instead of --test_arg",
            "suggest": 'bazel test {1} --test_filter="$TEST_GLOB"'
        }],
        ["bazel test:*"],
        'bazel test //other/target:tests --test_arg="bar"',
        "deny",
        "//other/target:tests",
        "Capture group works with different target",
    ),
    # -------------------------------------------------------------------------
    # Multiple feedback rules
    # -------------------------------------------------------------------------
    (
        [
            {"match": r"git push --force(?!-with-lease)", "message": "Use --force-with-lease"},
            {"match": r"bazel test.*--test_arg=", "message": "Use --test_filter instead"},
        ],
        ["git push:*", "bazel test:*"],
        "git push --force origin main",
        "deny",
        "--force-with-lease",
        "First matching feedback rule is used",
    ),
    (
        [
            {"match": r"git push --force(?!-with-lease)", "message": "Use --force-with-lease"},
            {"match": r"bazel test.*--test_arg=", "message": "Use --test_filter instead"},
        ],
        ["git push:*", "bazel test:*"],
        'bazel test //foo:bar --test_arg="x"',
        "deny",
        "--test_filter",
        "Second feedback rule matches when first doesn't",
    ),
    (
        [
            {"match": r"git push --force(?!-with-lease)", "message": "Use --force-with-lease"},
        ],
        ["git push:*"],
        "git push --force-with-lease origin main",
        "allow",
        None,
        "Negative lookahead allows --force-with-lease",
    ),
    # -------------------------------------------------------------------------
    # Feedback rules take priority over approval patterns
    # -------------------------------------------------------------------------
    (
        [{"match": r"rm -rf /", "message": "Refusing to delete root filesystem"}],
        ["rm:*"],
        "rm -rf /",
        "deny",
        "root filesystem",
        "Feedback rule blocks even when pattern would approve",
    ),
    # -------------------------------------------------------------------------
    # Invalid regex in feedback rule is skipped
    # -------------------------------------------------------------------------
    (
        [
            {"match": r"[invalid(regex", "message": "This rule has bad regex"},
            {"match": r"bazel test", "message": "Valid rule"},
        ],
        [],
        "bazel test //foo",
        "deny",
        "Valid rule",
        "Invalid regex rule is skipped, valid rule still works",
    ),
]

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
    # Wrapper stripping: time
    # -------------------------------------------------------------------------
    (
        ["pnpm install:*"],
        "time pnpm install",
        True,
        "time wrapper is stripped",
    ),
    (
        ["cargo build:*"],
        "time cargo build --release",
        True,
        "time wrapper with args",
    ),
    (
        ["cargo test:*"],
        "time timeout 30 cargo test",
        True,
        "time + timeout combined",
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
    # Command substitution: recursive checking ($() only, 1 level deep)
    # -------------------------------------------------------------------------
    (
        ["rm:*", "find:*"],
        "rm $(find . -name '*.tmp')",
        True,
        "$() approved when both outer and inner commands match patterns",
    ),
    (
        ["rm:*"],
        "rm $(find . -name '*.tmp')",
        False,
        "$() rejected when inner command has no matching pattern",
    ),
    (
        ["git diff:*", "git merge-base:*"],
        "git diff $(git merge-base HEAD main)..HEAD",
        True,
        "$() with git merge-base inside git diff",
    ),
    (
        ["echo:*"],
        "echo $(echo $(whoami))",
        False,
        "Nested $() substitution rejected (>1 level deep)",
    ),
    (
        ["echo:*"],
        'echo "$(date)"',
        True,
        "$() inside double quotes is literal — no substitution detected",
    ),
    (
        ["rm:*"],
        "rm `find . -name '*.tmp'`",
        False,
        "Backtick substitution always rejected (use $() syntax)",
    ),
    (
        ["git diff:*", "git merge-base:*", "grep:*"],
        "git diff $(git merge-base HEAD main)..HEAD | grep foo",
        True,
        "Pipe with $() substitution — all parts approved",
    ),
    (
        ["echo:*", "git log:*", "git status:*"],
        "echo $(git log --oneline && git status)",
        True,
        "$() with chained inner command — all inner segments approved",
    ),
    (
        ["echo:*"],
        "echo $(curl evil.com)",
        False,
        "$() rejected when inner command (curl) not in patterns",
    ),

    # -------------------------------------------------------------------------
    # Standalone variable assignments
    # -------------------------------------------------------------------------
    (
        ["./scripts/test.sh:*", "echo:*"],
        'SESSION_UUID=$(./scripts/test.sh 2>/tmp/stderr.txt) && echo "UUID=$SESSION_UUID"',
        True,
        "Standalone variable assignment with $() approved when inner command matches",
    ),
    (
        ["echo:*"],
        'RESULT=$(echo hello)',
        True,
        "Simple variable assignment with approved inner command",
    ),
    (
        ["echo:*"],
        'RESULT=$(curl evil.com)',
        False,
        "Variable assignment rejected when inner $() command not approved",
    ),
    (
        ["echo:*"],
        'FOO=bar BAZ=qux',
        True,
        "Standalone env var assignments with no command are safe",
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
    # git -C <cwd> normalization
    # -------------------------------------------------------------------------
    (
        ["git diff:*"],
        "git -C {cwd} diff",
        True,
        "git -C <cwd> normalized to git, matches git diff pattern",
    ),
    (
        ["git log:*"],
        "git -C {cwd} log --oneline",
        True,
        "git -C <cwd> with args normalized and matched",
    ),
    (
        ["git status:*"],
        "git -C /some/other/path status",
        False,
        "git -C <other_path> NOT normalized (different directory)",
    ),
    (
        ["git diff:*"],
        'git -C "{cwd}" diff',
        True,
        "git -C with double-quoted cwd path normalized",
    ),
    (
        ["git diff:*"],
        "git -C '{cwd}' diff",
        True,
        "git -C with single-quoted cwd path normalized",
    ),
    (
        ["git fetch:*", "git rebase:*"],
        "git -C {cwd} fetch && git -C {cwd} rebase origin/main",
        True,
        "Chained git -C commands both normalized",
    ),
    (
        ["git diff:*"],
        "timeout 30 git -C {cwd} diff",
        True,
        "timeout wrapper + git -C normalization combined",
    ),
    (
        ["git -C:*"],
        "git -C /some/other/path diff",
        True,
        "Explicit git -C pattern still works for other directories",
    ),

    # -------------------------------------------------------------------------
    # Path normalization (absolute <-> relative)
    # -------------------------------------------------------------------------
    (
        ["./scripts/run.sh:*"],
        "{cwd}/scripts/run.sh --flag",
        True,
        "Absolute path matches relative pattern when within cwd",
    ),
    (
        ["{cwd}/scripts/run.sh:*"],
        "./scripts/run.sh --flag",
        True,
        "Relative path matches absolute pattern when within cwd",
    ),
    (
        ["./scripts/run.sh:*"],
        "/some/other/path/scripts/run.sh",
        False,
        "Absolute path outside cwd does not match relative pattern",
    ),
    (
        ["./scripts/run.sh:*", "echo:*"],
        'NEW_UUID=$({cwd}/scripts/run.sh) && echo "UUID=$NEW_UUID"',
        True,
        "Absolute path in $() matches relative pattern via normalization",
    ),

    # -------------------------------------------------------------------------
    # Single quotes containing double quotes (grep alternation patterns)
    # -------------------------------------------------------------------------
    (
        ["grep:*", "head:*"],
        r'''grep -o '"description":"[^"]*"' some/file.jsonl | grep -i "mlfile\\|hourly\\|capacity" | head -10''',
        True,
        "Single-quoted arg with double quotes inside should not break pipe splitting",
    ),
    (
        ["grep:*"],
        '''grep -i "foo\\|bar\\|baz" file.txt''',
        True,
        "Grep alternation with backslash-pipe inside double quotes",
    ),
    (
        ["echo:*", "grep:*"],
        '''echo '"hello"' | grep -i "world"''',
        True,
        "Single-quoted double quotes followed by pipe and double-quoted arg",
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
        ["ls:*"],
        "lsof -ti :3456",
        False,
        "ls:* must not match lsof (prefix must end at word boundary)",
    ),
    (
        ["cat:*"],
        "caterpillar",
        False,
        "cat:* must not match caterpillar",
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


def run_hook(patterns: list[str], command: str, feedback_rules: list[dict] = None) -> dict:
    """Run the hook with given patterns and command.

    Returns dict with:
        - decision: "allow", "deny", or None (no output)
        - reason: the permissionDecisionReason if present

    Supports {cwd} placeholder in commands which gets replaced with the test's
    working directory (CLAUDE_PROJECT_DIR).
    """
    import tempfile
    import os

    if feedback_rules is None:
        feedback_rules = []

    # Create a temporary settings file with the patterns
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create fake home dir with .claude/settings.json
        fake_home = Path(tmpdir) / "home"
        fake_home.mkdir()
        settings_dir = fake_home / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.json"

        # Replace {cwd} placeholder with actual tmpdir path
        patterns = [p.replace("{cwd}", tmpdir) for p in patterns]
        command = command.replace("{cwd}", tmpdir)

        permissions = [f"Bash({p})" for p in patterns]
        settings_data = {"permissions": {"allow": permissions}}
        settings_file.write_text(json.dumps(settings_data))

        # Write feedback rules to separate file
        if feedback_rules:
            feedback_file = settings_dir / "command-feedback.json"
            feedback_file.write_text(json.dumps(feedback_rules))

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

        # Parse the output
        if result.stdout.strip():
            try:
                output = json.loads(result.stdout)
                hook_output = output.get("hookSpecificOutput", {})
                return {
                    "decision": hook_output.get("permissionDecision"),
                    "reason": hook_output.get("permissionDecisionReason", "")
                }
            except json.JSONDecodeError:
                pass

        return {"decision": None, "reason": ""}


def run_hook_legacy(patterns: list[str], command: str) -> bool:
    """Legacy wrapper for backward compatibility with existing tests."""
    result = run_hook(patterns, command)
    return result["decision"] == "allow"


def run_feedback_tests():
    """Run feedback rule tests and return (passed, failed, failures)."""
    passed = 0
    failed = 0
    failures = []

    print("-" * 70)
    print("FEEDBACK RULE TESTS")
    print("-" * 70)
    print()

    for feedback_rules, patterns, command, expected_decision, expected_msg, description in FEEDBACK_TEST_CASES:
        result = run_hook(patterns, command, feedback_rules)
        actual_decision = result["decision"]
        actual_reason = result["reason"]

        # Check decision matches
        decision_ok = actual_decision == expected_decision

        # Check message contains expected substring (if specified)
        message_ok = True
        if expected_msg and expected_decision == "deny":
            message_ok = expected_msg in actual_reason

        success = decision_ok and message_ok

        if success:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
            failures.append((feedback_rules, patterns, command, expected_decision, expected_msg, actual_decision, actual_reason, description))

        print(f"{status}  {description}")
        print(f"       Rules:    {[r.get('match') for r in feedback_rules]}")
        print(f"       Patterns: {patterns}")
        print(f"       Command:  {command}")
        print(f"       Expected: {expected_decision}")
        if not success:
            print(f"       Actual:   {actual_decision}")
            if expected_msg and expected_decision == "deny":
                print(f"       Expected msg to contain: {expected_msg}")
                print(f"       Actual msg: {actual_reason[:100]}...")
        print()

    return passed, failed, failures


def run_pattern_tests():
    """Run pattern matching tests and return (passed, failed, failures)."""
    passed = 0
    failed = 0
    failures = []

    print("-" * 70)
    print("PATTERN MATCHING TESTS")
    print("-" * 70)
    print()

    for patterns, command, should_allow, description in TEST_CASES:
        actual = run_hook_legacy(patterns, command)
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

    return passed, failed, failures


def run_logging_tests():
    """Run logging tests and return (passed, failed, failures)."""
    import tempfile
    import os

    passed = 0
    failed = 0
    failures = []

    print("-" * 70)
    print("LOGGING TESTS")
    print("-" * 70)
    print()

    LOGGING_TESTS = [
        # (patterns, command, expected_decision, description)
        ([], "mystery-cmd --flag", "no_patterns", "Logs when no patterns loaded"),
        (["cargo:*"], "unknown-cmd", "not_approved", "Logs when command not approved"),
        (["cargo:*"], "cargo test", None, "No log entry when approved"),
        (
            [{"match": r"rm -rf /", "message": "Nope"}],
            ["rm:*"],
            "rm -rf /",
            "denied",
            "Logs when denied by feedback rule",
        ),
    ]

    for test in LOGGING_TESTS:
        if len(test) == 4:
            patterns, command, expected_decision, description = test
            feedback_rules = []
        else:
            feedback_rules, patterns, command, expected_decision, description = test

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            fake_home.mkdir()
            settings_dir = fake_home / ".claude"
            settings_dir.mkdir()
            hooks_dir = settings_dir / "hooks"
            hooks_dir.mkdir()
            settings_file = settings_dir / "settings.json"

            permissions = [f"Bash({p})" for p in patterns]
            settings_data = {"permissions": {"allow": permissions}}
            settings_file.write_text(json.dumps(settings_data))

            if feedback_rules:
                feedback_file = settings_dir / "command-feedback.json"
                feedback_file.write_text(json.dumps(feedback_rules))

            input_data = json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command}
            })

            env = os.environ.copy()
            env["HOME"] = str(fake_home)
            env["CLAUDE_PROJECT_DIR"] = tmpdir

            subprocess.run(
                ["python3", str(HOOK_PATH)],
                input=input_data,
                capture_output=True,
                text=True,
                env=env,
            )

            log_file = hooks_dir / "approval.log"
            if expected_decision is None:
                # Should NOT have a log entry
                success = not log_file.exists() or log_file.read_text().strip() == ""
                if success:
                    status = "✓ PASS"
                    passed += 1
                else:
                    status = "✗ FAIL"
                    failed += 1
                    failures.append(description)
            else:
                # Should have a log entry with expected decision
                if log_file.exists():
                    entry = json.loads(log_file.read_text().strip().split("\n")[-1])
                    success = entry["decision"] == expected_decision and entry["command"] == command
                    if success:
                        status = "✓ PASS"
                        passed += 1
                    else:
                        status = "✗ FAIL"
                        failed += 1
                        failures.append(f"{description} (got decision={entry['decision']})")
                else:
                    status = "✗ FAIL"
                    failed += 1
                    failures.append(f"{description} (no log file created)")

            print(f"{status}  {description}")
            print(f"       Command:  {command}")
            print(f"       Expected log: {expected_decision}")
            print()

    return passed, failed, failures


def main():
    print("=" * 70)
    print("CLAUDE-APPROVE-HOOK TESTS")
    print("=" * 70)
    print()

    total_passed = 0
    total_failed = 0
    all_failures = []

    # Run feedback rule tests
    passed, failed, failures = run_feedback_tests()
    total_passed += passed
    total_failed += failed
    all_failures.extend(failures)

    # Run pattern matching tests
    passed, failed, failures = run_pattern_tests()
    total_passed += passed
    total_failed += failed
    all_failures.extend(failures)

    # Run logging tests
    passed, failed, failures = run_logging_tests()
    total_passed += passed
    total_failed += failed
    all_failures.extend(failures)

    print("=" * 70)
    print(f"RESULTS: {total_passed} passed, {total_failed} failed")
    print("=" * 70)

    if all_failures:
        print("\nFAILURES SUMMARY:")
        print(f"  {len(all_failures)} test(s) failed - see details above")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
