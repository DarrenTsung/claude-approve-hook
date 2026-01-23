---
allowed-tools: Bash, Read, Edit
description: Test a Bash command against approval patterns and optionally add permission.
---

**Mission:** Help the user debug why a Bash command wasn't auto-approved and optionally add a permission pattern.

**Tip:** Set `CLAUDE_PROJECT_DIR` environment variable in your shell config to skip the directory prompt.

**Process:**

1. Ask the user (in plain text, no tool):
   - What Bash command do you want to test?
   - If `CLAUDE_PROJECT_DIR` env var is set, use that as the working directory (mention this to the user)
   - Otherwise, ask: What working directory should be used for project settings? (default: current directory)

2. Run the test command:

   ```bash
   python3 ~/.claude/hooks/claude-approve-hook.py --test "<command>" --cwd "<directory>"
   ```

3. Show the user the output and explain:
   - Which patterns were checked
   - Whether wrappers (timeout, env vars, etc.) were stripped
   - Why it matched or didn't match

4. If the command was NOT approved, ask (in plain text):
   - Would you like to add a permission? Options: user settings, project settings, or skip

5. If user chose to add, edit the appropriate settings file directly:
   - User settings: ~/.claude/settings.json
   - Project settings: <cwd>/.claude/settings.local.json

   Add the pattern to `permissions.allow` array as `Bash(<pattern>:*)`.

6. Confirm the permission was added and show what was written.

**Start:**
What Bash command do you want to test, and what working directory should I use for project settings? (default: current directory)
