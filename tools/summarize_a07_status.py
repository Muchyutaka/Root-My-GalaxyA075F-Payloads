#!/usr/bin/env python3
"""Turn an A07 extraction run's JSON results into grouped GitHub check annotations.

The Arena sandbox can read check-run annotations through the GitHub API but cannot download
workflow logs or artifacts (both redirect to blob storage). Grouping the results here means the
whole fail-closed picture - which symbols resolved, which requirements are still missing, and
whether `task_struct.mm` was cross-verified - is visible without the artifact bundle.

Nothing is decided or invented here: this only re-reports what the extractor already wrote.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SYMBOL = re.compile(r"^symbol `")
PROFILE_VALUE = re.compile(r"\((?:missing profile value|profile JSON missing)\)")
PROFILE_EVIDENCE = re.compile(r"\((?:missing evidence string|evidence text contains)")
LIMIT = 1200


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text()) if path.is_file() else {}


def classify(missing: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {"symbols": [], "profileValues": [], "profileEvidence": [], "structural": []}
    for item in missing:
        if SYMBOL.match(item):
            groups["symbols"].append(item)
        elif PROFILE_VALUE.search(item):
            groups["profileValues"].append(item)
        elif PROFILE_EVIDENCE.search(item):
            groups["profileEvidence"].append(item)
        else:
            groups["structural"].append(item)
    return groups


def clip(text: str) -> str:
    return text if len(text) <= LIMIT else text[: LIMIT - 3] + "..."


def notices(directory: Path) -> list[str]:
    status = load(directory / "status.json")
    layouts = load(directory / "btf-layouts.json")
    symbols = load(directory / "symbol-offsets.json")
    missing = status.get("missing") or []
    groups = classify([str(item) for item in missing])
    mm = layouts.get("task_struct_mm") or {}
    offsets = symbols.get("offsetMacros") or {}
    out = [
        "A07 parse summary: ELF release="
        f"{symbols.get('kernelRelease') or status.get('kernelRelease') or 'NOT PARSED'}; "
        f"cross-verified ELF offsets={len(offsets)}; "
        f"task_struct.mm verified={mm.get('verified') is True}"
        + (f" (offset {mm['btfOffset']})" if mm.get("verified") is True else "")
        + f"; missing={len(missing)} "
        f"[symbols={len(groups['symbols'])}, profileValues={len(groups['profileValues'])}, "
        f"profileEvidence={len(groups['profileEvidence'])}, structural={len(groups['structural'])}]; "
        f"header ready={status.get('ready') is True}"
    ]
    if offsets:
        out.append("Resolved cross-verified ELF offsets: " + clip(", ".join(f"{k}={v}" for k, v in sorted(offsets.items()))))
    for key, label in (
        ("symbols", "Missing kernel symbols (must exist in ELF and kallsyms; never substituted)"),
        ("structural", "Structural blockers"),
        ("profileValues", "Missing A07 profile values (evidence-bearing, not derivable from ELF/BTF alone)"),
        ("profileEvidence", "Missing A07 profile evidence strings"),
    ):
        if groups[key]:
            out.append(f"{label}: " + clip("; ".join(groups[key])))
    derived = layouts.get("derivedMembers") or {}
    if derived:
        out.append("Nested BTF derivation: " + clip("; ".join(
            f"{macro}={info.get('status')}"
            + (f"@0x{info['offset']:x}" if isinstance(info.get("offset"), int) else "")
            + f" ({info.get('root')}.{info.get('path')})"
            for macro, info in sorted(derived.items())
        )))
    waiter = layouts.get("rtMutexWaiterLayoutCandidate")
    if waiter:
        out.append(f"rt_mutex_waiter layout measured from A07 BTF: {clip(str(waiter))}")
    diagnostics = layouts.get("incompleteStructDiagnostics") or {}
    for name in sorted(diagnostics):
        members = diagnostics[name].get("parsedMembers") or []
        out.append(f"struct {name}: pahole parsed {len(members)} members: " + clip(", ".join(members) or "(none)"))
    if status.get("warnings"):
        out.append("Warnings: " + clip("; ".join(str(w) for w in status["warnings"])))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("a07-target-output"))
    parser.add_argument("--github", action="store_true", help="emit ::notice:: workflow commands")
    args = parser.parse_args()
    for message in notices(args.output_dir):
        print(f"::notice::{message}" if args.github else message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
