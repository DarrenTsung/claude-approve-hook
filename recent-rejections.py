#!/usr/bin/env python3
"""Show recent rejected commands from the approval hook log.

Usage:
    python3 recent-rejections.py [--minutes N]

Reads ~/.claude/hooks/approval.log and shows non-approved commands
from the last N minutes (default: 5).
"""
import json
import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path.home() / ".claude" / "hooks" / "approval.log"


def main():
    parser = argparse.ArgumentParser(description="Show recent rejected commands")
    parser.add_argument(
        "--minutes", "-m", type=int, default=5,
        help="Look back this many minutes (default: 5)"
    )
    args = parser.parse_args()

    if not LOG_FILE.exists():
        sys.exit(0)

    cutoff = datetime.now().astimezone() - timedelta(minutes=args.minutes)
    recent = []

    for line in LOG_FILE.read_text().strip().split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = datetime.fromisoformat(entry["timestamp"])
        if ts >= cutoff:
            recent.append(entry)

    for entry in recent[-5:]:
        print(json.dumps(entry))


if __name__ == "__main__":
    main()
