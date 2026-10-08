#!/usr/bin/env python3
"""Create the three SM-A075F 6.12.38 entries in support/targets-v3.json.

The app resolves artifacts by rewriting an allowed raw.githubusercontent.com source URL to the
source commit it read. For that reason the feed points at this repository/ref, not at a GitHub
release URL. The build workflow also uploads the same files as release assets for manual download.

The app reads `flavor` and `kernelsu.version` directly; package names and module metadata
are not v3 manifest fields. The module/daemon pair is validated by the build workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote

MODEL = "SM-A075F"
KERNEL_VERSION = "6.12.38"
TARGET_ID = "a07-SM-A075F"

FLAVORS = (
    {
        "id": "kernelsu",
        "name": "KernelSU",
        "payload_suffix": "ksu330",
        "package": "me.weishu.kernelsu",
        "version": "3.3.0",
        "daemon": f"ksud-{TARGET_ID}-kdp",
        "module": f"android16-6.12_kernelsu-{TARGET_ID}-kdp.ko",
    },
    {
        "id": "kernelsu-next",
        "name": "KernelSU-Next",
        "payload_suffix": "ksun340",
        "package": "com.rifsxd.ksunext",
        "version": "3.4.0",
        "daemon": f"ksud-next-{TARGET_ID}-kdp",
        "module": f"android16-6.12_kernelsu-next-{TARGET_ID}-kdp.ko",
    },
    {
        "id": "resukisu",
        "name": "ReSukiSU",
        "payload_suffix": "rsksu420rc3",
        "package": "com.resukisu.resukisu",
        "version": "4.2.0-rc3",
        "daemon": f"ksud-rsksu-{TARGET_ID}-kdp",
        "module": f"android16-6.12_kernelsu-rsksu-{TARGET_ID}-kdp.ko",
    },
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, url: str) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise FileNotFoundError(f"required output artifact is missing or empty: {path}")
    return {
        "url": url,
        "size": path.stat().st_size,
        "sha256": sha256(path),
    }


def normalized_ref(ref: str) -> str:
    ref = ref.strip()
    if not ref or ref.startswith("/") or ".." in ref.split("/"):
        raise ValueError(f"invalid Git ref for raw artifact URLs: {ref!r}")
    return quote(ref, safe="/-._~")


def make_payload(
    flavor: dict[str, str],
    app_path: Path,
    daemon_path: Path,
    module_path: Path,
    repo: str,
    ref: str,
    kernel_release: str,
) -> dict[str, object]:
    root = f"https://raw.githubusercontent.com/{repo}/{normalized_ref(ref)}"
    app_url = f"{root}/artifacts/{TARGET_ID}/cve-2026-43499-app.so"
    daemon_url = f"{root}/kernelsu/{flavor['daemon']}"
    kernel_versions = [KERNEL_VERSION]
    if kernel_release != KERNEL_VERSION:
        kernel_versions.append(kernel_release)
    # Fail before modifying the feed if the matching module was not produced.
    artifact(module_path, f"{root}/kernelsu/{flavor['module']}")
    payload_id = f"{TARGET_ID}-{flavor['payload_suffix']}"
    entry: dict[str, object] = {
        "payloadId": payload_id,
        "displayName": f"Galaxy A07 ({MODEL}) | Kernel {KERNEL_VERSION} | {flavor['name']} {flavor['version']}",
        "models": [MODEL],
        "kernelVersions": kernel_versions,
        "flavor": flavor["id"],
        "exploit": artifact(app_path, app_url),
        "kernelsu": {
            **artifact(daemon_path, daemon_url),
            "version": flavor["version"],
        },
    }
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, default=Path("support/targets-v3.json"))
    parser.add_argument("--repo", required=True, help="GitHub owner/repository for the raw source URLs")
    parser.add_argument("--ref", required=True, help="Branch configured as the payload source in the app")
    parser.add_argument("--kernel-release", required=True, help="Exact UTS_RELEASE extracted from kernel.elf")
    parser.add_argument("--app", type=Path, default=Path(f"artifacts/{TARGET_ID}/cve-2026-43499-app.so"))
    parser.add_argument("--kernelsu-dir", type=Path, default=Path("kernelsu"))
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise SystemExit(f"invalid GitHub repository: {args.repo!r}")
    if not args.kernel_release.startswith(KERNEL_VERSION + "-") and args.kernel_release != KERNEL_VERSION:
        raise SystemExit(
            f"kernel release {args.kernel_release!r} is not a {KERNEL_VERSION} release"
        )

    feed_path = args.feed
    feed = json.loads(feed_path.read_text())
    if feed.get("schemaVersion") != 3 or not isinstance(feed.get("payloads"), list):
        raise SystemExit("support feed must be schemaVersion 3 with a payloads array")

    app_path = args.app
    new_entries = []
    ids = set()
    for flavor in FLAVORS:
        daemon_path = args.kernelsu_dir / flavor["daemon"]
        module_path = args.kernelsu_dir / flavor["module"]
        entry = make_payload(
            flavor,
            app_path,
            daemon_path,
            module_path,
            args.repo,
            args.ref,
            args.kernel_release,
        )
        payload_id = str(entry["payloadId"])
        if payload_id in ids:
            raise SystemExit(f"duplicate generated payload id: {payload_id}")
        ids.add(payload_id)
        new_entries.append(entry)

    existing = feed["payloads"]
    other_entries = [entry for entry in existing if entry.get("payloadId") not in ids]
    conflicting = [
        entry for entry in other_entries
        if MODEL in entry.get("models", [])
        and KERNEL_VERSION in entry.get("kernelVersions", [])
        and entry.get("flavor", "kernelsu") in {item["id"] for item in FLAVORS}
    ]
    if conflicting:
        names = ", ".join(str(entry.get("payloadId", "<missing id>")) for entry in conflicting)
        raise SystemExit(
            "refusing to add duplicate SM-A075F 6.12.38 flavor rows with different ids: " + names
        )

    # Replacements retain their original list position; first-time entries are appended in flavor order.
    old_by_id = {entry.get("payloadId"): index for index, entry in enumerate(existing)}
    merged = list(existing)
    for entry in new_entries:
        if entry["payloadId"] in old_by_id:
            merged[old_by_id[entry["payloadId"]]] = entry
        else:
            merged.append(entry)
    feed["payloads"] = merged
    feed_path.write_text(json.dumps(feed, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(new_entries)} SM-A075F 6.12.38 flavor entries to {feed_path}")
    for entry in new_entries:
        print(f"{entry['payloadId']}: kernelsu.version={entry['kernelsu']['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
