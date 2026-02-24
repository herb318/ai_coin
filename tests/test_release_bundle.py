import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.create_release_bundle import build_bundle


class TestCreateReleaseBundle(unittest.TestCase):
    def test_build_bundle_creates_zip_with_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            binary = root / "dpuin"
            output = root / "release"
            binary.write_bytes(b"test-binary")

            zip_path = build_bundle(binary_path=binary, target="linux-x64", output_dir=output)

            self.assertTrue(zip_path.exists())
            self.assertEqual(zip_path.name, "dpuin-linux-x64.zip")
            with zipfile.ZipFile(zip_path, "r") as archive:
                names = set(archive.namelist())
            self.assertIn("dpuin-linux-x64/dpuin", names)
            self.assertIn("dpuin-linux-x64/RUN_ME_FIRST.txt", names)
            self.assertIn("dpuin-linux-x64/README.md", names)
            self.assertIn("dpuin-linux-x64/.env.example", names)

    def test_build_bundle_requires_existing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            missing_binary = root / "missing-binary"
            with self.assertRaises(FileNotFoundError):
                build_bundle(binary_path=missing_binary, target="linux-x64", output_dir=root / "release")


if __name__ == "__main__":
    unittest.main()
