#!/usr/bin/env python3
"""Download the IBM track dataset into data/, which git ignores.

Uses only the standard library so it runs the same on Linux, macOS and Windows.
Re-running it downloads the dataset again and overwrites the local copy.
"""

import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

URL = "https://github.com/ShardulB6/PatchRader/releases/download/data-v1/patchrader-data.zip"
SHA256 = "2267687c62e76842ba65feb60a62cc23fa8c829e1dc99237900e507e32225d3f"
ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    print(f"Downloading {URL} (about 110 MB)...")
    with urllib.request.urlopen(URL) as response:
        payload = response.read()

    digest = hashlib.sha256(payload).hexdigest()
    if digest != SHA256:
        sys.exit(f"Checksum mismatch: expected {SHA256}, got {digest}")

    print("Extracting to data/ (about 850 MB)...")
    # The release zip holds IBM/README.md, IBM/DATA_DICTIONARY.md and IBM/data.zip.
    # Paths inside the inner zip already start with data/.
    with zipfile.ZipFile(io.BytesIO(payload)) as outer:
        with zipfile.ZipFile(io.BytesIO(outer.read("IBM/data.zip"))) as inner:
            inner.extractall(ROOT)
        for name in ("README.md", "DATA_DICTIONARY.md"):
            (ROOT / "data" / name).write_bytes(outer.read(f"IBM/{name}"))

    print("Done. See data/README.md and data/DATA_DICTIONARY.md.")


if __name__ == "__main__":
    main()
