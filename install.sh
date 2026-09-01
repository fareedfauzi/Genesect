#!/bin/sh
set -eu

echo "=========================================="
echo " PseudoNote Extended Installer (Linux/macOS) "
echo "=========================================="

if [ -n "${IDAUSR-}" ]; then
    IDA_PLUGINS="$IDAUSR/plugins"
elif [ "$(uname -s)" = "Darwin" ]; then
    IDA_PLUGINS="$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins"
else
    IDA_PLUGINS="$HOME/.idapro/plugins"
fi

# Allow overriding plugin directory via argument (only if running locally)
if [ "$#" -eq 1 ]; then
    IDA_PLUGINS="$1"
fi

mkdir -p "$IDA_PLUGINS"

echo "Target Directory: $IDA_PLUGINS"

echo "[*] Cleaning up classic PseudoNote installations..."
rm -f "$IDA_PLUGINS/pseudonote.py"
rm -rf "$IDA_PLUGINS/pseudonote"
rm -f "$IDA_PLUGINS/pseudonote.ini"
rm -f "$HOME/.pseudonote.ini"

# Determine if local or remote install
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) 2>/dev/null || SCRIPT_DIR="."

if [ -f "$SCRIPT_DIR/PseudoNoteExtended.py" ] && [ -d "$SCRIPT_DIR/pseudonote_extended" ]; then
    echo "[*] Local installation detected."
    cp -f "$SCRIPT_DIR/PseudoNoteExtended.py" "$IDA_PLUGINS/"
    rm -rf "$IDA_PLUGINS/pseudonote_extended"
    cp -R "$SCRIPT_DIR/pseudonote_extended" "$IDA_PLUGINS/"
else
    echo "[*] Remote installation detected. Downloading latest version from GitHub..."
    if ! command -v curl >/dev/null 2>&1; then
        echo "ERROR: curl is required for remote installation." >&2
        exit 1
    fi
    if ! command -v unzip >/dev/null 2>&1; then
        echo "ERROR: unzip is required for remote installation." >&2
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    curl -fsSL https://github.com/fareedfauzi/PseudoNote-Extended/archive/refs/heads/main.zip -o "$TMP_DIR/main.zip"
    unzip -q "$TMP_DIR/main.zip" -d "$TMP_DIR"
    
    cp -f "$TMP_DIR/PseudoNote-Extended-main/PseudoNoteExtended.py" "$IDA_PLUGINS/"
    rm -rf "$IDA_PLUGINS/pseudonote_extended"
    cp -R "$TMP_DIR/PseudoNote-Extended-main/pseudonote_extended" "$IDA_PLUGINS/"
    
    rm -rf "$TMP_DIR"
fi

echo "[*] Installation completed successfully."
echo "[!] Please ensure Python dependencies are installed:"
echo "    pip install openai httpx PySide6"
echo "[*] Restart IDA Pro to load the updated plugin."
