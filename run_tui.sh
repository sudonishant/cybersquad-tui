#!/usr/bin/env bash
# Cyber Squad Forensic TUI Launcher
set -e

# Resolve directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if rich is installed, if not, guide or install
if ! python3 -c "import rich" >/dev/null 2>&1; then
    echo "[*] Installing required 'rich' library..."
    pip install --break-system-packages -r requirements.txt 2>/dev/null || sudo apt update && sudo apt install -y python3-rich
fi

# Launch TUI
python3 "$SCRIPT_DIR/app.py" "$@"
