"""Validate complete, architecture-specific artifacts and create their manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

RID_ASSETS = {
    "win-x64": ("netmail_sieve.dll", "x86_64", "windows"),
    "linux-x64": ("libnetmail_sieve.so", "x86_64", "linux"),
    "osx-arm64": ("libnetmail_sieve.dylib", "aarch64", "macos"),
    "osx-x64": ("libnetmail_sieve.dylib", "x86_64", "macos"),
}


def package(root, output):
    root = Path(root)
    manifest = {"schema_version": 1, "abi_version": 2, "assets": []}
    versions, revisions = set(), set()
    for rid, (name, arch, os_name) in RID_ASSETS.items():
        directory = root / "runtimes" / rid / "native"
        binary, metadata = directory / name, directory / "runtime-info.json"
        info = json.loads(metadata.read_text(encoding="utf-8"))
        if (info["arch"], info["os"], info["abi_version"]) != (arch, os_name, 2):
            raise ValueError(f"Wrong architecture/ABI for {rid}: {info}")
        if not info.get("source_revision"):
            raise ValueError(f"Missing source revision for {rid}")
        versions.add(info["version"])
        revisions.add(info["source_revision"])
        manifest["assets"].append({"rid": rid, "path": binary.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "runtime": info})
    if len(versions) != 1 or len(revisions) != 1:
        raise ValueError("Mixed versions or source revisions in runtime bundle")
    manifest["version"] = versions.pop()
    manifest["source_revision"] = revisions.pop()
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(root / "manifest.json", "manifest.json")
        for asset in manifest["assets"]:
            path = root / asset["path"]
            archive.write(path, asset["path"])
            metadata = path.with_name("runtime-info.json")
            archive.write(metadata, metadata.relative_to(root).as_posix())
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("output")
    args = parser.parse_args()
    print(json.dumps(package(args.root, args.output)))
