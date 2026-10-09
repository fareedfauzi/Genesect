"""Build deterministic Genesect release archives and hash manifests."""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
DEFAULT_ARCHIVE_NAME = "Genesect.zip"
REQUIRED_FILES = (
    "Genesect.py",
)
OPTIONAL_FILES = (
    "README.md",
    "COMPATIBILITY.md",
    "KNOWN_ISSUES.md",
    "MIGRATION.md",
    "CHANGELOG.md",
    "install.bat",
    "install.ps1",
    "install.sh",
)


def metadata_version():
    metadata = (ROOT / "genesect" / "metadata.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', metadata, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find __version__ in genesect/metadata.py")
    return match.group(1)


def release_files():
    files = []
    missing_required = [name for name in REQUIRED_FILES if not (ROOT / name).is_file()]
    if missing_required:
        raise FileNotFoundError("Missing required release files: " + ", ".join(missing_required))

    files.extend(ROOT / name for name in REQUIRED_FILES)
    files.extend(ROOT / name for name in OPTIONAL_FILES if (ROOT / name).is_file())
    files.extend(path for path in (ROOT / "docs").rglob("*") if path.is_file())
    files.extend(path for path in (ROOT / "genesect").rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def write_archive(path, files, manifest_bytes):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file_path in files:
            info = zipfile.ZipInfo(file_path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, file_path.read_bytes())
        info = zipfile.ZipInfo("release_manifest.json", (2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest_bytes)


def build(version=None):
    version = version or metadata_version()
    DIST.mkdir(exist_ok=True)
    archive = DIST / DEFAULT_ARCHIVE_NAME
    versioned_archive = DIST / f"Genesect-{version}.zip"
    files = release_files()
    manifest = {
        "name": "Genesect",
        "version": version,
        "files": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    write_archive(archive, files, manifest_bytes)
    if versioned_archive != archive:
        shutil.copyfile(archive, versioned_archive)

    sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
    (DIST / f"{archive.name}.sha256").write_text(f"{sha256}  {archive.name}\n", encoding="utf-8")
    print(archive)
    print(sha256)
    print(versioned_archive)
    print(hashlib.sha256(versioned_archive.read_bytes()).hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="Override the version from genesect/metadata.py")
    args = parser.parse_args()
    build(version=args.version)
