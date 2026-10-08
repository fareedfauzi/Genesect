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
    echo "[*] Remote installation detected. Downloading latest release from GitHub..."
    if ! command -v curl >/dev/null 2>&1; then
        echo "ERROR: curl is required for remote installation." >&2
        exit 1
    fi
    if ! command -v unzip >/dev/null 2>&1; then
        echo "ERROR: unzip is required for remote installation." >&2
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

    ZIP_PATH="$TMP_DIR/PseudoNote-Extended.zip"
    RELEASE_API="https://api.github.com/repos/fareedfauzi/PseudoNote-Extended/releases/latest"
    FALLBACK_URL="https://github.com/fareedfauzi/PseudoNote-Extended/archive/refs/heads/main.zip"
    RELEASE_URL=$(curl -fsSL "$RELEASE_API" |
        sed -n 's/.*"browser_download_url": "\(https:[^"]*\/PseudoNote-Extended[^"]*\.zip\)".*/\1/p' |
        sed -n '1p') || true

    if [ -z "$RELEASE_URL" ]; then
        RELEASE_URL="https://github.com/fareedfauzi/PseudoNote-Extended/releases/latest/download/PseudoNote-Extended.zip"
    fi

    echo "[*] Downloading release asset: $RELEASE_URL"
    if ! curl -fsSL "$RELEASE_URL" -o "$ZIP_PATH"; then
        echo "[!] Release zip unavailable. Falling back to source archive..."
        curl -fsSL "$FALLBACK_URL" -o "$ZIP_PATH"
    fi

    unzip -q "$ZIP_PATH" -d "$TMP_DIR"

    EXTRACTED_DIR=""
    if [ -f "$TMP_DIR/PseudoNoteExtended.py" ] && [ -d "$TMP_DIR/pseudonote_extended" ]; then
        EXTRACTED_DIR="$TMP_DIR"
    else
        EXTRACTED_DIR=$(find "$TMP_DIR" -type d -exec sh -c '
            for dir do
                if [ -f "$dir/PseudoNoteExtended.py" ] && [ -d "$dir/pseudonote_extended" ]; then
                    printf "%s\n" "$dir"
                    exit 0
                fi
            done
            exit 1
        ' sh {} + | sed -n '1p') || true
    fi

    if [ -z "$EXTRACTED_DIR" ]; then
        echo "ERROR: Downloaded archive does not contain PseudoNoteExtended.py and pseudonote_extended." >&2
        exit 1
    fi
    
    cp -f "$EXTRACTED_DIR/PseudoNoteExtended.py" "$IDA_PLUGINS/"
    rm -rf "$IDA_PLUGINS/pseudonote_extended"
    cp -R "$EXTRACTED_DIR/pseudonote_extended" "$IDA_PLUGINS/"
fi

echo "[*] Installation completed successfully."
echo "[!] Please ensure Python dependencies are installed:"
echo "    pip install openai httpx PySide6"
echo "[*] Restart IDA Pro to load the updated plugin."
