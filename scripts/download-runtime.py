#!/usr/bin/env python3
"""Download only reviewed runtime URLs and verify their pinned SHA256."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def download(url, destination):
    hashes = json.loads(Path(__file__).with_name("runtime-downloads.json").read_text())
    expected = hashes.get(url)
    if not expected:
        raise ValueError("runtime URL has no pinned checksum: " + url)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".partial")
    try:
        subprocess.run(["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry", "4",
                        "--retry-delay", "2", "--connect-timeout", "20", "--max-time", "300",
                        "-o", str(temporary), url], check=True)
        digest = hashlib.sha256()
        with temporary.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError("runtime SHA256 mismatch: " + url)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: download-runtime.py URL DESTINATION")
    download(*sys.argv[1:])
