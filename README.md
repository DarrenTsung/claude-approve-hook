# approve-variants

A Claude Code hook that auto-approves Bash command variants you've already approved.

## The Problem

Claude Code's built-in permission system only supports prefix matching. This means you repeatedly grant permission for slight variations of the same command:

- `cargo test`
- `timeout 60 cargo test`
- `RUST_BACKTRACE=1 cargo test`
- `timeout 60 RUST_BACKTRACE=1 cargo test --package foo`

Inspired by [Matthew Rocklin's approach](https://matthewrocklin.com/ai-zealotry/#appendix-permissions-file) to replace Claude's permission system with custom Python logic.

**Key difference from the original**: This hook reads your existing approved patterns directly from Claude's `settings.json` files, so you don't need to maintain a separate permissions list.

## What It Does

If you've approved `Bash(cargo test:*)`, this hook also approves variants with safe wrappers:

| Wrapper | Example |
|---------|---------|
| `timeout N` | `timeout 60 cargo test` |
| `nice [-n N]` | `nice -n 10 cargo test` |
| `env` | `env cargo test` |
| Environment variables | `RUST_BACKTRACE=1 cargo test` |
| `.venv/bin/` paths | `.venv/bin/pytest` |

For chained commands (`&&`, `||`, `;`, `|`), every segment must match an approved pattern.

Command substitution (`$(...)` and backticks) is always rejected for safety.

## Installation

```bash
./install.sh
```

This symlinks `approve-variants.py` to `~/.claude/hooks/`.

Then add the hook to your Claude settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["~/.claude/hooks/approve-variants.py"]
      }
    ]
  }
}
```

## Debug

Test manually by piping JSON to the hook:

```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "timeout 30 cargo test"}}' | python3 ~/.claude/hooks/approve-variants.py
```

Run the test suite:

```bash
python3 test_approve_variants.py
```
