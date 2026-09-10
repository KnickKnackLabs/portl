"""Release completeness checks use local fixtures, not GitHub access."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "release_assets", Path(__file__).resolve().parents[1] / "verify-release-assets.py"
)
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.tag = "v0.14.1"
        self.names = assets.expected_assets(self.tag)
        for name in self.names:
            content = name.encode()
            (self.directory / name).write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            (self.directory / f"{name}.sha256").write_text(f"{digest}  {name}\n")

    def test_complete_release(self):
        self.assertEqual(len(self.names), 11)
        self.assertEqual(sum(name.endswith(".pkg") for name in self.names), 2)
        assets.verify(self.tag, self.directory)

    def test_missing_macos_assets_fail(self):
        for path in self.directory.glob("*-apple-darwin.*"):
            path.unlink()
        with self.assertRaisesRegex(ValueError, "missing="):
            assets.verify(self.tag, self.directory)

    def test_each_asset_and_checksum_is_required(self):
        for path in self.directory.iterdir():
            with self.subTest(name=path.name):
                content = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(ValueError, "Release asset mismatch"):
                    assets.verify(self.tag, self.directory)
                path.write_bytes(content)

    def test_corrupt_asset_fails(self):
        (self.directory / min(self.names)).write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "Invalid checksum"):
            assets.verify(self.tag, self.directory)

    def test_empty_asset_fails(self):
        (self.directory / min(self.names)).write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "Empty asset"):
            assets.verify(self.tag, self.directory)

    def test_checksum_cannot_name_another_file(self):
        name = min(self.names)
        checksum = self.directory / f"{name}.sha256"
        checksum.write_text(checksum.read_text().replace(name, "../other"))
        with self.assertRaisesRegex(ValueError, "Invalid checksum or filename"):
            assets.verify(self.tag, self.directory)

    def test_unexpected_asset_fails(self):
        (self.directory / "old-release.pkg").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "unexpected=.*old-release.pkg"):
            assets.verify(self.tag, self.directory)

    def test_wrong_tag_fails(self):
        with self.assertRaisesRegex(ValueError, "Release asset mismatch"):
            assets.verify("v0.14.0", self.directory)

    def test_invalid_tag_fails(self):
        for tag in ("", "../v0.14.1", "0.14.1", "v0.14.1/other"):
            with (
                self.subTest(tag=tag),
                self.assertRaisesRegex(ValueError, "Invalid release tag"),
            ):
                assets.expected_assets(tag)


if __name__ == "__main__":
    unittest.main()
