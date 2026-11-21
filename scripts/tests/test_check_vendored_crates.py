"""Vendored-crate coverage checks use synthetic metadata, not cargo."""

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "check_vendored_crates", Path(__file__).resolve().parents[1] / "check-vendored-crates.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def package(name, version, directory):
    return {"name": name, "version": version, "manifest_path": str(directory / "Cargo.toml")}


class VendoredCrateTests(unittest.TestCase):
    registry = Path("/registry/src")

    def test_only_vendored_copy_passes(self):
        packages = {"t": [package("netwatch", "0.19.3", check.VENDOR / "netwatch")]}
        self.assertEqual(check.problems(["netwatch"], packages), [])

    def test_second_registry_copy_fails(self):
        packages = {
            "t": [
                package("netwatch", "0.19.3", check.VENDOR / "netwatch"),
                package("netwatch", "0.20.0", self.registry / "netwatch-0.20.0"),
            ]
        }
        [problem] = check.problems(["netwatch"], packages)
        self.assertIn("netwatch 0.20.0", problem)

    def test_registry_only_copy_fails(self):
        packages = {"t": [package("netdev", "0.47.0", self.registry / "netdev-0.47.0")]}
        [problem] = check.problems(["netdev"], packages)
        self.assertIn("bypassing vendor/netdev", problem)

    def test_vendored_crate_missing_from_graph_fails(self):
        [problem] = check.problems(["netdev"], {"t": []})
        self.assertIn("not in the dependency graph", problem)


if __name__ == "__main__":
    unittest.main()
