#!/usr/bin/env python3
"""Fail when a shipped target resolves a vendored crate from anywhere but vendor/.

`[patch.crates-io]` only replaces the version it matches. If a dependency later
requires a semver-incompatible release, Cargo resolves a second, unpatched copy,
and because portl also depends on netwatch directly the patch stays "used", so
Cargo prints no warning. Inspect the resolved graph per shipped target instead.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor"
TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
)


def vendored_crates():
    return sorted(path.parent.name for path in VENDOR.glob("*/Cargo.toml"))


def resolved_packages(target):
    output = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(output)
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    return [package for package in metadata["packages"] if package["id"] in resolved]


def problems(crates, packages_by_target):
    found = []
    for target, packages in packages_by_target.items():
        for name in crates:
            vendored = (VENDOR / name).resolve()
            copies = [package for package in packages if package["name"] == name]
            if not copies:
                found.append(f"{target}: {name} is vendored but not in the dependency graph")
            for package in copies:
                manifest = Path(package["manifest_path"]).resolve()
                if manifest.parent != vendored:
                    found.append(
                        f"{target}: {name} {package['version']} resolves from {manifest.parent}, "
                        f"bypassing vendor/{name}"
                    )
    return found


def main():
    crates = vendored_crates()
    found = problems(crates, {target: resolved_packages(target) for target in TARGETS})
    if found:
        print("::error ::vendored crate patches no longer cover every resolved copy")
        print("\n".join(found))
        print("Re-apply vendor/patches/*.patch to the new upstream version (see vendor/README.md).")
        return 1
    print(f"OK: {', '.join(crates)} resolve only from vendor/ on {len(TARGETS)} targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
