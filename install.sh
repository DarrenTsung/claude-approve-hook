#!/bin/bash
# Install claude-approve-hook by symlinking to ~/.claude/hooks/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$HOME/.claude/hooks"

mkdir -p "$HOOKS_DIR"

ln -sf "$SCRIPT_DIR/claude-approve-hook.py" "$HOOKS_DIR/claude-approve-hook.py"
echo "Linked: $HOOKS_DIR/claude-approve-hook.py -> $SCRIPT_DIR/claude-approve-hook.py"
