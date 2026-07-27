#!/bin/bash
# Cybersecurity Daily Log — Cron Runner
# Called daily by cron to generate and push the journal entry.
# All output goes to stdout for cron email/logging.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Starting daily log generation..."

# Ensure we have the latest from remote (in case of manual edits)
git pull --rebase origin main 2>/dev/null || true

# Run the generator
python3 generate.py

echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Daily log complete."
