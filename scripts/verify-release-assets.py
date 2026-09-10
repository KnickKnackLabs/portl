"""Reject incomplete release asset sets and invalid SHA-256 sidecars."""

import hashlib
import re
import sys
from pathlib import Path


def expected_assets(tag):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", tag):
        raise ValueError(f"Invalid release tag: {tag}")
    assets = {f"PortlFFI-{tag}-apple.xcframework.zip"}
    for target in (
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ):
        formats = ["tar.gz", "tar.zst"]
        if target.endswith("apple-darwin"):
            formats.append("pkg")
        assets.update(f"portl-{tag}-{target}.{suffix}" for suffix in formats)
    return assets


def verify(tag, directory):
    assets = expected_assets(tag)
    expected = assets | {f"{name}.sha256" for name in assets}
    actual = {path.name for path in directory.iterdir()}
    if actual != expected:
        raise ValueError(
            f"Release asset mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    for name in sorted(assets):
        path = directory / name
        if path.stat().st_size == 0:
            raise ValueError(f"Empty asset: {name}")
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        sidecar = (directory / f"{name}.sha256").read_text().strip()
        if sidecar not in {f"{digest}  {name}", f"{digest} *{name}"}:
            raise ValueError(f"Invalid checksum or filename: {name}.sha256")
        print(f"OK: {name}")
    print(f"Verified {len(assets)} assets and {len(assets)} checksums for {tag}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: verify-release-assets.py TAG DIRECTORY")
    verify(sys.argv[1], Path(sys.argv[2]))
