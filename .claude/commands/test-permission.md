---
allowed-tools: Bash, Read, Edit
description: Test a Bash command against approval patterns and optionally add permission.
---

**Mission:** Help the user debug why a Bash command wasn't auto-approved and optionally add a permission pattern.

**Process:**

1. First, check if `CLAUDE_PROJECT_DIR` is set:
   ```bash
   echo $CLAUDE_PROJECT_DIR
   ```

2. Check the log file for recent rejections (last 5 minutes):
   ```bash
   python3 recent-rejections.py
   ```

3. **If recent rejections were found AND the user didn't specify a command:**
   - Show the recent rejected commands with timestamps
   - Automatically test the most recent one (skip asking the user)
   - Jump to step 5

4. **If no recent rejections or user specified a command:**
   - Ask the user (in plain text, no tool):
     - What Bash command do you want to test?
     - If `CLAUDE_PROJECT_DIR` was set (non-empty), tell the user you'll use that as the working directory
     - Otherwise, ask: What working directory should be used for project settings? (default: current directory)

5. Run the test command:

   ```bash
   python3 ~/.claude/hooks/claude-approve-hook.py --test "<command>" --cwd "<directory>"
   ```

6. Show the user the output and explain:
   - Which patterns were checked
   - Whether wrappers (timeout, env vars, etc.) were stripped
   - Why it matched or didn't match

7. If the command was NOT approved, ask (in plain text):
   - Would you like to add a permission? Options: user settings, project settings, or skip

8. If user chose to add, edit the appropriate settings file directly:
   - User settings: ~/.claude/settings.json
   - Project settings: <cwd>/.claude/settings.local.json

   Add the pattern to `permissions.allow` array as `Bash(<pattern>:*)`.

9. Confirm the permission was added and show what was written.

**Start:**
First run `echo $CLAUDE_PROJECT_DIR` to check if the environment variable is set, then check the log file for recent rejections. If recent rejections are found, automatically start testing the most recent one. Otherwise, ask the user what command they want to test.
