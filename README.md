# claude-approve-hook

A Claude Code hook that auto-approves Bash command variants you've already approved.

## The Problem

Claude Code's built-in permission system only supports prefix matching. This means you repeatedly grant permission for slight variations of the same command:

- `cargo test`
- `timeout 60 cargo test`
- `RUST_BACKTRACE=1 cargo test`
- `timeout 60 RUST_BACKTRACE=1 cargo test --package foo`

Inspired by [Matthew Rocklin's approach](https://matthewrocklin.com/ai-zealotry/#example-problem-incomplete-permissions) to replace Claude's permission system with custom Python logic.

**Key difference from the original**: This hook reads your existing approved patterns directly from Claude's `settings.json` files, so you don't need to maintain a separate permissions list.

## What It Does

If you've approved `Bash(cargo test:*)`, this hook also approves variants with safe wrappers:

| Wrapper               | Example                       |
| --------------------- | ----------------------------- |
| `timeout N`           | `timeout 60 cargo test`       |
| `nice [-n N]`         | `nice -n 10 cargo test`       |
| `env`                 | `env cargo test`              |
| Environment variables | `RUST_BACKTRACE=1 cargo test` |
| `.venv/bin/` paths    | `.venv/bin/pytest`            |

For chained commands (`&&`, `||`, `;`, `|`), every segment must match an approved pattern.

Command substitution (`$(...)` and backticks) is always rejected for safety.

## Installation

```bash
./install.sh
```

This symlinks `claude-approve-hook.py` to `~/.claude/hooks/`.

Then add the hook to your Claude settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["~/.claude/hooks/claude-approve-hook.py"]
      }
    ]
  }
}
```

## Claude Code Slash Command

This repo includes a `/test-permission` command for Claude Code:

```
/test-permission
```

This interactively:
1. Tests the command against your approval patterns
2. Shows why it matched or didn't
3. Offers to add a permission if not approved

**Tip:** Set the `CLAUDE_PROJECT_DIR` environment variable in your shell config to skip the directory prompt:

```bash
export CLAUDE_PROJECT_DIR=~/my/project
```

## CLI Test Mode

Debug why a command wasn't auto-approved:

```bash
python3 ~/.claude/hooks/claude-approve-hook.py --test "rustup update"

# With project directory context (loads project-specific patterns)
python3 ~/.claude/hooks/claude-approve-hook.py --test "cargo test" --cwd /path/to/project
```

This shows:
- All loaded patterns and their source files
- How the command was parsed (wrappers stripped, segments split)
- Which pattern matched (or didn't)
- Suggested pattern to add if not approved

## Debug

Test manually by piping JSON to the hook:

```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "timeout 30 cargo test"}}' | python3 ~/.claude/hooks/claude-approve-hook.py
```

Run the test suite:

```bash
python3 test_claude_approve_hook.py
```
