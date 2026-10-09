"""Verify every file hash recorded inside a Genesect release."""

import hashlib
import json
import pathlib
import sys
import zipfile


def verify(path):
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("release_manifest.json"))
        failures = [
            name for name, expected in manifest["files"].items()
            if hashlib.sha256(archive.read(name)).hexdigest() != expected
        ]
    print(f"Archive files: {len(manifest['files'])}; hash failures: {len(failures)}")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "dist/Genesect.zip")
    raise SystemExit(verify(target))
