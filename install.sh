#!/bin/sh
set -eu

# PseudoNote Extended installer for IDA on Linux and macOS.
# Usage: sh install.sh [IDA_PLUGINS_DIRECTORY]

usage() {
    cat <<'EOF'
Usage: sh install.sh [IDA_PLUGINS_DIRECTORY]

With no argument, the installer uses:
  $IDAUSR/plugins                                      when IDAUSR is set
  ~/Library/Application Support/Hex-Rays/IDA Pro/plugins on macOS
  ~/.idapro/plugins                                    on Linux
EOF
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
SOURCE_ENTRY="$SCRIPT_DIR/PseudoNoteExtended.py"
SOURCE_PACKAGE="$SCRIPT_DIR/pseudonote_extended"

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    IDA_PLUGINS=$1
elif [ -n "${IDAUSR-}" ]; then
    IDA_PLUGINS="$IDAUSR/plugins"
elif [ "$(uname -s)" = "Darwin" ]; then
    IDA_PLUGINS="$HOME/Library/Application Support/Hex-Rays/IDA Pro/plugins"
else
    IDA_PLUGINS="$HOME/.idapro/plugins"
fi

if [ ! -f "$SOURCE_ENTRY" ]; then
    echo "ERROR: Missing source entry point: $SOURCE_ENTRY" >&2
    exit 1
fi
if [ ! -d "$SOURCE_PACKAGE" ]; then
    echo "ERROR: Missing source package: $SOURCE_PACKAGE" >&2
    exit 1
fi

TARGET_PACKAGE="$IDA_PLUGINS/pseudonote_extended"
mkdir -p "$TARGET_PACKAGE"

echo "Installing PseudoNote Extended into:"
echo "  $IDA_PLUGINS"

# Copy source files without carrying local bytecode caches into IDA.
find "$SOURCE_PACKAGE" -type f \
    ! -path '*/__pycache__/*' \
    ! -name '*.pyc' \
    ! -name '*.pyo' \
    -print | while IFS= read -r source_file; do
        relative_path=${source_file#"$SOURCE_PACKAGE"/}
        destination="$TARGET_PACKAGE/$relative_path"
        mkdir -p "$(dirname "$destination")"
        cp -f "$source_file" "$destination"
    done

cp -f "$SOURCE_ENTRY" "$IDA_PLUGINS/PseudoNoteExtended.py"

echo "Installation completed successfully."
echo "Restart IDA to load the updated plugin."
