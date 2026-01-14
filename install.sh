#!/bin/bash
# Install approve-variants hook by symlinking to ~/.claude/hooks/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$HOME/.claude/hooks"

mkdir -p "$HOOKS_DIR"

ln -sf "$SCRIPT_DIR/approve-variants.py" "$HOOKS_DIR/approve-variants.py"
echo "Linked: $HOOKS_DIR/approve-variants.py -> $SCRIPT_DIR/approve-variants.py"
