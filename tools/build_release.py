"""Build a deterministic PseudoNote Extended release archive and hash manifest."""

import hashlib
import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = "1.0.0"
ARCHIVE = DIST / f"PseudoNote-Extended-{VERSION}.zip"
INCLUDE_FILES = (
    "PseudoNoteExtended.py", "README.md", "COMPATIBILITY.md", "KNOWN_ISSUES.md",
    "MIGRATION.md", "CHANGELOG.md", "install.bat", "install.sh",
)


def release_files():
    files = [ROOT / name for name in INCLUDE_FILES]
    files.extend(path for path in (ROOT / "docs").rglob("*") if path.is_file())
    files.extend(path for path in (ROOT / "pseudonote_extended").rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def build():
    DIST.mkdir(exist_ok=True)
    files = release_files()
    manifest = {
        "name": "PseudoNote Extended",
        "version": VERSION,
        "files": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo("release_manifest.json", (2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest_bytes)
    print(ARCHIVE)
    print(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest())


if __name__ == "__main__":
    build()
