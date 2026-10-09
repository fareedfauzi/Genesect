#!/bin/sh
set -eu

echo "=========================================="
echo " Genesect Installer (Linux/macOS) "
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

echo "[*] Cleaning up legacy installations..."
LEGACY_ENTRY="Pseudo""NoteExtended.py"
LEGACY_BASE="pseudo""note"
rm -f "$IDA_PLUGINS/Genesect.py"
rm -f "$IDA_PLUGINS/$LEGACY_ENTRY"
rm -f "$IDA_PLUGINS/$LEGACY_BASE.py"
rm -rf "$IDA_PLUGINS/$LEGACY_BASE"
rm -f "$IDA_PLUGINS/$LEGACY_BASE.ini"
rm -f "$HOME/.$LEGACY_BASE.ini"

# Determine if local or remote install
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) 2>/dev/null || SCRIPT_DIR="."

if [ -f "$SCRIPT_DIR/Genesect.py" ] && [ -d "$SCRIPT_DIR/genesect" ]; then
    echo "[*] Local installation detected."
    cp -f "$SCRIPT_DIR/Genesect.py" "$IDA_PLUGINS/"
    rm -rf "$IDA_PLUGINS/genesect"
    cp -R "$SCRIPT_DIR/genesect" "$IDA_PLUGINS/"
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

    ZIP_PATH="$TMP_DIR/Genesect.zip"
    RELEASE_API="https://api.github.com/repos/fareedfauzi/Genesect/releases/latest"
    FALLBACK_URL="https://github.com/fareedfauzi/Genesect/archive/refs/heads/main.zip"
    RELEASE_URL=$(curl -fsSL "$RELEASE_API" |
        sed -n 's/.*"browser_download_url": "\(https:[^"]*\/Genesect[^"]*\.zip\)".*/\1/p' |
        sed -n '1p') || true

    if [ -z "$RELEASE_URL" ]; then
        RELEASE_URL="https://github.com/fareedfauzi/Genesect/releases/latest/download/Genesect.zip"
    fi

    echo "[*] Downloading release asset: $RELEASE_URL"
    if ! curl -fsSL "$RELEASE_URL" -o "$ZIP_PATH"; then
        echo "[!] Release zip unavailable. Falling back to source archive..."
        curl -fsSL "$FALLBACK_URL" -o "$ZIP_PATH"
    fi

    unzip -q "$ZIP_PATH" -d "$TMP_DIR"

    EXTRACTED_DIR=""
    if [ -f "$TMP_DIR/Genesect.py" ] && [ -d "$TMP_DIR/genesect" ]; then
        EXTRACTED_DIR="$TMP_DIR"
    else
        EXTRACTED_DIR=$(find "$TMP_DIR" -type d -exec sh -c '
            for dir do
                if [ -f "$dir/Genesect.py" ] && [ -d "$dir/genesect" ]; then
                    printf "%s\n" "$dir"
                    exit 0
                fi
            done
            exit 1
        ' sh {} + | sed -n '1p') || true
    fi

    if [ -z "$EXTRACTED_DIR" ]; then
        echo "ERROR: Downloaded archive does not contain Genesect.py and genesect." >&2
        exit 1
    fi
    
    cp -f "$EXTRACTED_DIR/Genesect.py" "$IDA_PLUGINS/"
    rm -rf "$IDA_PLUGINS/genesect"
    cp -R "$EXTRACTED_DIR/genesect" "$IDA_PLUGINS/"
fi

echo "[*] Installation completed successfully."
echo "[!] Please ensure Python dependencies are installed:"
echo "    pip install openai httpx PySide6"
echo "[*] Restart IDA Pro to load the updated plugin."
