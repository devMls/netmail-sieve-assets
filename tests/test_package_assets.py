import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("package_assets", Path(__file__).parents[1] / "tools/package_assets.py")
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class PackageTests(unittest.TestCase):
    def fixture(self, root):
        for rid, (name, arch, system) in assets.RID_ASSETS.items():
            directory = root / "runtimes" / rid / "native"
            directory.mkdir(parents=True)
            (directory / name).write_bytes(rid.encode())
            (directory / "runtime-info.json").write_text(json.dumps({
                "arch": arch, "os": system, "abi_version": 2,
                "version": "0.2.0", "source_revision": "same-commit"}), encoding="utf-8")

    def test_macos_libraries_with_same_basename_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            assets.package(root, root / "bundle.zip")
            with zipfile.ZipFile(root / "bundle.zip") as archive:
                for rid in ["osx-x64", "osx-arm64"]:
                    self.assertEqual(archive.read(f"runtimes/{rid}/native/libnetmail_sieve.dylib"), rid.encode())

    def test_wrong_macos_architecture_blocks_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            metadata = root / "runtimes/osx-x64/native/runtime-info.json"
            info = json.loads(metadata.read_text())
            info["arch"] = "aarch64"
            metadata.write_text(json.dumps(info))
            with self.assertRaises(ValueError):
                assets.package(root, root / "bundle.zip")

    def test_mixed_source_revisions_block_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            metadata = root / "runtimes/win-x64/native/runtime-info.json"
            info = json.loads(metadata.read_text())
            info["source_revision"] = "different-commit"
            metadata.write_text(json.dumps(info))
            with self.assertRaises(ValueError):
                assets.package(root, root / "bundle.zip")

    def test_missing_platform_blocks_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                assets.package(Path(temporary), Path(temporary) / "bundle.zip")


if __name__ == "__main__":
    unittest.main()
