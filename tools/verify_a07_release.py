#!/usr/bin/env python3
"""Verify *every* exact SM-A075F firmware release asset before parsing any of them.

The GitHub Releases API reports SHA-256 digests for uploaded assets. Check the metadata
before download, then fetch it again after download so a mutable release cannot silently
swap an asset between enumeration and verification. This tool never opens a device or writes
firmware anywhere outside the runner's working directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

TAG = "a07-firmware-v1"
ASSETS = (
    "boot.img", "vendor_boot.img", "dtbo.img", "preloader.img",
    "lk-verified.img", "param.bin", "up_param.bin", "kernel.raw",
    "kernel.elf", "ramdisk.cpio", "kallsyms.txt", "vmlinux.btf",
    "SM-A075F_16_Opensource.zip",
)
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")


def release_assets(metadata: dict) -> dict[str, dict]:
    if metadata.get("tag_name") != TAG or metadata.get("draft") is not False:
        raise ValueError(f"expected published release {TAG}")
    items = metadata.get("assets")
    if not isinstance(items, list):
        raise ValueError("release has no assets list")
    by_name = {}
    for asset in items:
        name = asset.get("name")
        if name in by_name:
            raise ValueError(f"duplicate release asset name: {name}")
        by_name[name] = asset
    if set(by_name) != set(ASSETS):
        raise ValueError(f"release asset names differ: missing={sorted(set(ASSETS) - set(by_name))}, "
                         f"unexpected={sorted(set(by_name) - set(ASSETS))}")
    for name in ASSETS:
        item = by_name[name]
        if item.get("state") != "uploaded" or not isinstance(item.get("size"), int) or item["size"] <= 0:
            raise ValueError(f"incomplete release asset: {name}")
        if not isinstance(item.get("id"), int) or item["id"] <= 0:
            raise ValueError(f"missing release asset ID: {name}")
        if not DIGEST.fullmatch(item.get("digest") or ""):
            raise ValueError(f"missing/invalid GitHub SHA-256 for {name}")
    return by_name


def verify(before: dict, after: dict, directory: Path) -> dict:
    first, second = release_assets(before), release_assets(after)
    if before.get("id") != after.get("id"):
        raise ValueError("release identity changed during download")
    expected = {name: {key: first[name][key] for key in ("id", "size", "digest")} for name in ASSETS}
    actual = {name: {key: second[name][key] for key in ("id", "size", "digest")} for name in ASSETS}
    if expected != actual:
        raise ValueError("release asset IDs, sizes or SHA-256 digests changed during download")
    for name in ASSETS:
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != expected[name]["size"]:
            raise ValueError(f"missing, symlinked or incorrect-size download: {name}")
        h = hashlib.sha256()
        with path.open("rb") as data:
            for chunk in iter(lambda: data.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != expected[name]["digest"].removeprefix("sha256:"):
            raise ValueError(f"SHA-256 mismatch: {name}")
        print(f"verified {name}: {expected[name]['digest']}")
    return {"releaseTag": TAG, "releaseId": before["id"], "assets": expected}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", required=True, type=Path)
    p.add_argument("--after", type=Path)
    p.add_argument("--assets", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    before = json.loads(args.before.read_text())
    release_assets(before)  # fail before downloading anything on missing/invalid release metadata
    if args.after is None:
        if any((args.assets, args.output)):
            p.error("--assets and --output require --after")
        print(f"release {TAG}: all {len(ASSETS)} assets have API SHA-256 digests")
        return
    if args.assets is None or args.output is None:
        p.error("--after requires --assets and --output")
    receipt = verify(before, json.loads(args.after.read_text()), args.assets)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
