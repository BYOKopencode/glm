#!/usr/bin/env bash
# One-shot local setup. Safe to re-run.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> integrity check (no dependencies needed)"
python3 -m py_compile main.py
python3 main.py --selfcheck

echo
echo "==> installing python dependencies"
python3 -m pip install --user --upgrade -r requirements.txt

echo
echo "==> installing the matching chromium build"
# This is the step whose absence causes:
#   BrowserType.launch: Executable doesn't exist at
#   ~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell
python3 -m playwright install chromium

# System libraries. Present on Cloud Shell and most desktops; missing on bare
# containers. Non-fatal because it needs sudo and is often unnecessary.
if command -v sudo >/dev/null 2>&1; then
  echo
  echo "==> installing system libraries (optional, may prompt for sudo)"
  sudo python3 -m playwright install-deps chromium || \
    echo "    skipped -- only a problem if chromium fails to launch"
fi

echo
echo "Done. Start the server with:"
echo "    python3 main.py"
echo "or with debug logging:"
echo "    DEBUG=1 python3 main.py"
