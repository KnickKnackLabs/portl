#!/usr/bin/env python3
"""Verify that every nextest-skipped test is documented in the manifest."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = WORKSPACE_ROOT / "crates/portl-cli/tests/skipped-tests.toml"


@dataclass(frozen=True, order=True)
class SkippedTest:
    package: str
    binary: str
    kind: str
    name: str

    @classmethod
    def from_manifest(cls, entry: dict[str, object]) -> "SkippedTest":
        missing = [
            key
            for key in ("package", "binary", "kind", "name")
            if not isinstance(entry.get(key), str) or not entry[key]
        ]
        if missing:
            raise ValueError(f"manifest entry is missing fields: {', '.join(missing)}")
        justification = entry.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            raise ValueError(f"{entry['name']}: justification must be a non-empty string")
        if "\n" in justification or "\r" in justification:
            raise ValueError(f"{entry['name']}: justification must be one line")
        return cls(
            package=str(entry["package"]),
            binary=str(entry["binary"]),
            kind=str(entry["kind"]),
            name=str(entry["name"]),
        )

    def label(self) -> str:
        return f"{self.package} {self.kind} {self.binary}::{self.name}"


def nextest_inventory() -> dict[str, object]:
    result = subprocess.run(
        [
            "cargo",
            "nextest",
            "list",
            "--message-format",
            "json",
            "--workspace",
            "--all-features",
        ],
        cwd=WORKSPACE_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        suites: dict[str, object] = {}
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            suites.update(obj.get("rust-suites", {}))
        return {"rust-suites": suites}


def skipped_tests_from_nextest() -> set[SkippedTest]:
    skipped: set[SkippedTest] = set()
    for suite in nextest_inventory().get("rust-suites", {}).values():
        package = suite["package-name"]
        binary = suite["binary-name"]
        kind = suite["kind"]
        for name, testcase in suite["testcases"].items():
            filter_match = testcase.get("filter-match", {})
            filter_skipped = filter_match.get("status") == "mismatch"
            if testcase.get("ignored") or filter_skipped:
                skipped.add(
                    SkippedTest(
                        package=package,
                        binary=binary,
                        kind=kind,
                        name=name,
                    )
                )
    return skipped


def skipped_tests_from_manifest() -> set[SkippedTest]:
    with MANIFEST_PATH.open("rb") as handle:
        manifest = tomllib.load(handle)
    entries = manifest.get("skipped_tests")
    if not isinstance(entries, list):
        raise ValueError("manifest must contain [[skipped_tests]] entries")
    return {SkippedTest.from_manifest(entry) for entry in entries}


def report_difference(title: str, tests: set[SkippedTest]) -> None:
    if not tests:
        return
    print(title, file=sys.stderr)
    for test in sorted(tests):
        print(f"  - {test.label()}", file=sys.stderr)


def main() -> int:
    actual = skipped_tests_from_nextest()
    manifest = skipped_tests_from_manifest()
    missing = actual - manifest
    stale = manifest - actual

    if missing or stale:
        report_difference("Skipped tests missing from manifest:", missing)
        report_difference("Manifest entries that do not exist or are no longer skipped:", stale)
        return 1

    print(f"skipped-tests manifest OK: {len(actual)} skipped tests documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
