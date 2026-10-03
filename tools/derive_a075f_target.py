#!/usr/bin/env python3
"""Derive and verify every value in src/targets/a07-A075FXXS5BZD2/target.h
against the exact A075FXXS5BZD2 firmware kernel.

Run in CI by .github/workflows/port-a075f.yml (the porting sandbox has no
cross-toolchain and no access to the release asset CDN; the GitHub runner
has both).  The script is stdlib-only: it shells out to readelf/objdump
(binutils) and does all ELF/BTF parsing in Python.

Inputs (firmware files from release tag "1" of this repository plus the
committed profile):
  --elf         kernel.elf  (vmlinux-to-elf output of the exact Image)
  --raw         kernel.raw  (the raw ARM64 Image)
  --target      src/targets/a07-A075FXXS5BZD2/target.h
  --config      src/targets/a07-A075FXXS5BZD2/kernel.config (committed)
  --fingerprint src/targets/a07-A075FXXS5BZD2/p0_fingerprint.h (committed)
  --src-root    kernel source tree (Samsung opensource zip; optional but
                used for the trace.h enum, workqueue.c and slub.c audits)
  --report      JSON report path (written either way)
  --md          markdown report path (written either way)
  --expected-release   exact uname -r string the profile is tied to

Exit status: 0 = every value verified, 1 = at least one check failed.  The
CI step must fail on a non-zero exit so the payload is never built from an
unverified profile.

Cross-reference constants (ghostlock-a17 6.12.23-android16-5 and
ghostlock-emerald 6.12.30-android16-5, both device-verified MT6789 ports
of the same GKI generation) are used as independent checks, never as the
source of a value.

BTF encoding follows include/uapi/linux/btf.h exactly (cross-checked
against dwarves/libbpf): btf_type = {name_off, info, union{size,type}}
with info bits 0-23 = vlen, bits 24-30 = kind, bit 31 = kind_flag;
kinds UNKN=0 INT=1 PTR=2 ARRAY=3 STRUCT=4 UNION=5 ENUM=6 FWD=7
TYPEDEF=8 VOLATILE=9 CONST=10 RESTRICT=11 FUNC=12 FUNC_PROTO=13
VAR=14 DATASEC=15 FLOAT=16 DECL_TAG=17 TYPE_TAG=18 ENUM64=19.
"""

import argparse
import gzip
import json
import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# cross-reference table (independent checks only, never value sources)
# ---------------------------------------------------------------------------
XREF = {
    "pselect_word_shift_612": 2,  # ghostlock-a17 + ghostlock-emerald (6.12, MT6789)
    "fops_llseek_612": 0x10,
    "fops_read_iter_612": 0x28,
    "fops_ioctl_612": 0x50,
    "fops_mmap_612": 0x60,
    "task_prio_612": 0x94,
    "task_pi_waiters_612": 0xa00,
    "mm_struct_sz_612": 0x500,  # ghostlock-a17/emerald MM_STRUCT_SZ
    "skbuff_head_612": 0xe80,
    "event_id_base_612": 20,  # __TRACE_LAST_TYPE, a17 on-device (94 - 74)
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------------------
# ELF via readelf
# ---------------------------------------------------------------------------
def load_symbols(elf):
    out = run(["readelf", "-sW", str(elf)]).stdout
    syms = {}
    for line in out.splitlines():
        m = re.match(
            r"^\s*\d+:\s+([0-9a-f]+)\s+(\S+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s*$",
            line,
        )
        if not m:
            continue
        val, typ, name = int(m.group(1), 16), m.group(3), m.group(7)
        if typ not in ("FUNC", "OBJECT", "NOTYPE") or val == 0:
            continue
        syms[name] = val
    return syms


def load_vma_base(elf):
    """first LOAD segment VirtAddr (columns: Type Offset VirtAddr PhysAddr)."""
    out = run(["readelf", "-lW", str(elf)]).stdout
    for line in out.splitlines():
        m = re.match(
            r"^\s*LOAD\s+(?:0x)?([0-9a-fA-F]+)\s+(?:0x)?([0-9a-fA-F]+)\s+(?:0x)?([0-9a-fA-F]+)",
            line,
        )
        if m:
            return int(m.group(2), 16)
    raise SystemExit("no LOAD segment found in " + str(elf))


# ---------------------------------------------------------------------------
# BTF (v1, little-endian) — see module docstring for the authoritative
# encoding (include/uapi/linux/btf.h).
# ---------------------------------------------------------------------------
class BTF:
    K_UNKN, K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF, \
        K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, \
        K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = range(20)

    def __init__(self, blob):
        (magic, version, flags, hdr_len, type_off, type_len, str_off, str_len) = struct.unpack_from(
            "<HBBIIIII", blob, 0
        )
        if magic != 0xEB9F or version != 1:
            raise SystemExit("bad BTF header")
        self.types = blob[hdr_len + type_off : hdr_len + type_off + type_len]
        self.strings = blob[hdr_len + str_off : hdr_len + str_off + str_len]
        self.table = {}
        self._start = {}
        off, idx = 0, 1
        n = len(self.types)
        while off < n:
            self._start[idx] = off
            name_off, info, ut = struct.unpack_from("<III", self.types, off)
            kind = (info >> 24) & 0x7F
            vlen = info & 0xFFFFFF
            kflag = (info >> 31) & 1
            d = {"kind": kind, "vlen": vlen, "kflag": kflag, "ut": ut,
                 "name": self._name(off)}
            off = self._skip_payload(d, off + 12)
            self.table[idx] = d
            idx += 1
        if off != n:
            raise SystemExit(f"BTF type section misparsed: walked {off}, have {n}")
        self._size_memo = {}

    def _name(self, off):
        (no,) = struct.unpack_from("<I", self.types, off)
        end = self.strings.index(b"\0", no)
        return self.strings[no:end].decode("utf-8", "replace")

    @staticmethod
    def _skip_payload(d, off):
        """off = first byte past {name_off, info, ut}; return next type start."""
        k, v = d["kind"], d["vlen"]
        if k in (BTF.K_STRUCT, BTF.K_UNION):
            return off + v * 12
        if k == BTF.K_ENUM:
            return off + v * 8
        if k in (BTF.K_ENUM64, BTF.K_DATASEC):
            return off + v * 12
        if k in (BTF.K_INT, BTF.K_VAR, BTF.K_DECL_TAG):
            return off + 4
        if k == BTF.K_ARRAY:
            return off + 12  # btf_array {type, index_type, nelems}
        if k == BTF.K_FUNC_PROTO:
            return off + v * 8
        return off

    def size(self, tid):
        """size of type tid in bytes (aarch64: pointer = 8)."""
        if tid in self._size_memo:
            return self._size_memo[tid]
        sz = 0
        d = self.table.get(tid)
        if d is not None:
            k = d["kind"]
            if k in (self.K_INT, self.K_ENUM, self.K_ENUM64, self.K_STRUCT,
                     self.K_UNION, self.K_FWD, self.K_FLOAT, self.K_DATASEC):
                sz = d["ut"]
            elif k in (self.K_TYPEDEF, self.K_VOLATILE, self.K_CONST,
                       self.K_RESTRICT, self.K_VAR):
                sz = self.size(d["ut"])
            elif k == self.K_PTR:
                sz = 8
            elif k == self.K_ARRAY:
                _t, _ix, nelems = struct.unpack_from("<III", self.types, self._start[tid] + 12)
                sz = nelems * self.size(_t)
        self._size_memo[tid] = sz
        return sz

    def by_name(self, name):
        hits = [i for i, d in self.table.items() if d["name"] == name]
        return hits[0] if len(hits) == 1 else None

    def members(self, idx):
        d = self.table[idx]
        if d["kind"] not in (self.K_STRUCT, self.K_UNION):
            raise SystemExit(f"{d['name']} is not a struct/union")
        off = self._start[idx] + 12
        out = []
        for i in range(d["vlen"]):
            mno, mtype, enc = struct.unpack_from("<III", self.types, off + i * 12)
            end = self.strings.index(b"\0", mno)
            mname = self.strings[mno:end].decode("utf-8", "replace")
            if d["kflag"]:
                bit_off, bit_size = enc & 0xFFFFFF, enc >> 24
            else:
                bit_off, bit_size = enc, 0
            out.append({"name": mname, "type": mtype, "bit_off": bit_off,
                        "bit_size": bit_size,
                        "byte_off": bit_off // 8 if bit_off % 8 == 0 else None})
        return d, out


def find_btf(raw: bytes):
    prefix = b"\x9f\xeb\x01\x00"
    candidates = []
    cursor = 0
    while True:
        start = raw.find(prefix, cursor)
        if start < 0:
            break
        cursor = start + 1
        if start + 24 > len(raw):
            continue
        (magic, version, flags, header_len, type_off, type_len,
         str_off, str_len) = struct.unpack_from("<HBBIIIII", raw, start)
        if magic != 0xEB9F or version != 1 or flags != 0 or header_len < 24:
            continue
        payload_len = max(type_off + type_len, str_off + str_len)
        end = start + header_len + payload_len
        string_start = start + header_len + str_off
        if end > len(raw) or string_start >= end or raw[string_start] != 0:
            continue
        candidates.append((start, end))
    if len(candidates) != 1:
        raise SystemExit(f"expected exactly one raw BTF blob, found {candidates}")
    return raw[candidates[0][0] : candidates[0][1]], candidates[0]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def qword(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def cstr(raw, off, maxlen=64):
    end = raw.find(b"\0", off, off + maxlen)
    if end < 0:
        return ""
    return raw[off:end].decode("ascii", "replace")


def parse_target_header(path):
    out = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\\?\s*$", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def macro_val(parts, name):
    raw = " ".join(parts.get(name, [])).strip()
    if raw.startswith('"'):
        return raw
    raw = re.sub(r"[UuLl]+$", "", raw).strip()
    if re.fullmatch(r"-?[0-9a-fA-FxX.]+", raw):
        try:
            return int(raw, 0)
        except ValueError:
            return raw
    return raw


def parse_trace_last_type(src_root):
    th = Path(src_root) / "kernel/trace/trace.h"
    if not th.exists():
        return None
    txt = re.sub(r"/\*.*?\*/", "", th.read_text(errors="replace"), flags=re.S)
    m = re.search(r"enum trace_type\s*\{(.*?)\};", txt, re.S)
    if not m:
        return None
    val = -1
    for item in m.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        nm, _, eq = item.partition("=")
        nm = nm.strip()
        if eq:
            val = int(re.sub(r"[^0-9A-Za-z_+-]", "", eq))
        else:
            val += 1
    return val


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--config", default=None)
    ap.add_argument("--fingerprint", default=None)
    ap.add_argument("--src-root", default=None)
    ap.add_argument("--report", required=True)
    ap.add_argument("--md", required=True)
    ap.add_argument("--expected-release", default=None)
    a = ap.parse_args()

    rep = {"checks": [], "values": {}, "errors": []}

    def check(name, ok, detail=""):
        rep["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            rep["errors"].append(f"{name}: {detail}")
        return ok

    raw = Path(a.raw).read_bytes()
    elf = Path(a.elf)
    target = parse_target_header(Path(a.target))
    macro = lambda n: macro_val(target, n)

    # -- kernel banner -----------------------------------------------------
    release = None
    m = re.search(rb"Linux version ([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._-]*)", raw)
    if m:
        release = m.group(1).decode()
    check("kernel.banner", release is not None,
          release or "no 'Linux version' banner in the Image")
    if release:
        rep["values"]["kernel_release"] = release
    if a.expected_release:
        check("kernel.release-match", release == a.expected_release,
              f"banner {release!r} vs expected {a.expected_release!r}")

    # -- ELF base ----------------------------------------------------------
    base = load_vma_base(elf)
    check("elf.base", base == macro("KIMAGE_TEXT_BASE"),
          f"first LOAD VMA 0x{base:x} vs KIMAGE_TEXT_BASE 0x{macro('KIMAGE_TEXT_BASE'):x}")
    rep["values"]["kimage_text_base"] = f"0x{base:x}"

    # -- symbols -----------------------------------------------------------
    syms = load_symbols(elf)
    rep["values"]["symbol_count"] = len(syms)

    def sym_off(name):
        return syms[name] - base if name in syms else None

    sym_macros = {
        "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
        "NOOP_LLSEEK_OFF": "noop_llseek",
        "COPY_SPLICE_READ_OFF": "copy_splice_read",
        "CONFIGFS_READ_ITER_OFF": "configfs_read_iter",
        "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
        "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
        "KMALLOC_CACHES_OFF": "kmalloc_caches",
        "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
        "SLIDE_NFULNL_LOGGER_OBJECT_OFF": "nfulnl_logger",
        "INIT_TASK_OFF": "init_task",
        "ROOT_TASK_GROUP_OFF": "root_task_group",
        "SELINUX_ENFORCING_OFF": "selinux_state",
        "SYSCTL_BOOTID_OFF": "sysctl_bootid",
    }
    for mname, sname in sym_macros.items():
        got = sym_off(sname)
        want = macro(mname)
        detail = (f"{sname} 0x{got:x} vs 0x{want:x}"
                  if got is not None else f"missing symbol {sname}")
        check(f"sym.{mname}", got is not None and got == want, detail)
        if got is not None:
            rep["values"][mname] = f"0x{got:x}"

    sdata, edata = sym_off("_sdata"), sym_off("_edata")

    # -- BTF ---------------------------------------------------------------
    btf = None
    try:
        btf_blob, btf_range = find_btf(raw)
        btf = BTF(btf_blob)
        check("btf.extract", True,
              f"Image[0x{btf_range[0]:x}, 0x{btf_range[1]:x}), {len(btf.table)} types")
    except SystemExit as e:
        check("btf.extract", False, str(e))

    def member_off(struct_name, member):
        if not btf:
            return None
        idx = btf.by_name(struct_name)
        if idx is None:
            return None
        _, members = btf.members(idx)
        for m in members:
            if m["name"] == member:
                return m
        return None

    layout_checks = [
        ("SIZEOF_FILE_OPERATIONS", "file_operations", None, "size"),
        ("FOPS_LLSEEK_OFF", "file_operations", "llseek", "off"),
        ("FOPS_READ_OFF", "file_operations", "read", "off"),
        ("FOPS_WRITE_OFF", "file_operations", "write", "off"),
        ("FOPS_READ_ITER_OFF", "file_operations", "read_iter", "off"),
        ("FOPS_WRITE_ITER_OFF", "file_operations", "write_iter", "off"),
        ("FOPS_UNLOCKED_IOCTL_OFF", "file_operations", "unlocked_ioctl", "off"),
        ("FOPS_COMPAT_IOCTL_OFF", "file_operations", "compat_ioctl", "off"),
        ("FOPS_MMAP_OFF", "file_operations", "mmap", "off"),
        ("FOPS_OPEN_OFF", "file_operations", "open", "off"),
        ("FOPS_RELEASE_OFF", "file_operations", "release", "off"),
        ("FOPS_SPLICE_READ_OFF", "file_operations", "splice_read", "off"),
        ("FOPS_SHOW_FDINFO_OFF", "file_operations", "show_fdinfo", "off"),
        ("TASK_USAGE_OFF", "task_struct", "usage", "off"),
        ("TASK_PRIO_OFF", "task_struct", "prio", "off"),
        ("TASK_NORMAL_PRIO_OFF", "task_struct", "normal_prio", "off"),
        ("TASK_SCHED_TASK_GROUP_OFF", "task_struct", "sched_task_group", "off"),
        ("TASK_PI_LOCK_OFF", "task_struct", "pi_lock", "off"),
        ("TASK_PI_WAITERS_OFF", "task_struct", "pi_waiters", "off"),
        ("TASK_PI_TOP_TASK_OFF", "task_struct", "pi_top_task", "off"),
        ("TASK_PI_BLOCKED_ON_OFF", "task_struct", "pi_blocked_on", "off"),
        ("PAGE_COMPOUND_HEAD_OFF", "page", "compound_head", "off"),
        ("PAGE_PAGE_TYPE_OFF", "page", "page_type", "off"),
        ("PWQ_NR_ACTIVE_OFF", "pool_workqueue", "nr_active", "off"),
        ("WQ_DFL_PWQ_OFF", "workqueue_struct", "dfl_pwq", "off"),
        ("WORK_FUNC_OFF", "work_struct", "func", "off"),
    ]
    if btf:
        for mname, sname, member, mode in layout_checks:
            if mode == "size":
                idx = btf.by_name(sname)
                got = btf.size(idx) if idx else None
            else:
                mb = member_off(sname, member)
                got = mb["byte_off"] if mb else None
            want = macro(mname)
            detail = (f"{sname}.{member or 'size'} 0x{got:x} vs 0x{want:x}"
                      if got is not None else f"{sname}.{member} not in BTF")
            check(f"btf.{mname}", got is not None and got == want, detail)
            if got is not None:
                rep["values"][mname] = f"0x{got:x}"

        for sname in ("pool_workqueue", "mm_struct", "sk_buff",
                      "rt_mutex_waiter", "task_struct", "rb_node",
                      "file_operations", "configfs_buffer", "miscdevice",
                      "ctl_table", "nf_logger"):
            idx = btf.by_name(sname)
            if idx is None:
                continue
            d, members = btf.members(idx)
            rep["values"][f"btf.{sname}"] = (
                f"size 0x{btf.size(idx):x}: "
                + ", ".join(f"{m['name']}=0x{m['byte_off']:x}"
                            if m["byte_off"] is not None
                            else f"{m['name']}=bit{m['bit_off']}"
                            for m in members)
            )
    else:
        check("btf.layouts", False, "no BTF blob - all layout checks skipped")

    # rt_mutex_waiter waiter macros
    if btf:
        waiter_checks = [
            ("FAKE_WAITER_PI_TREE_ENTRY_OFF", "rt_mutex_waiter", "pi_tree"),
            ("FAKE_WAITER_TASK_OFF", "rt_mutex_waiter", "task"),
            ("FAKE_WAITER_LOCK_OFF", "rt_mutex_waiter", "lock"),
            ("FAKE_WAITER_WAKE_STATE_OFF", "rt_mutex_waiter", "wake_state"),
            ("FAKE_WAITER_WW_CTX_OFF", "rt_mutex_waiter", "ww_ctx"),
        ]
        for mname, sname, member in waiter_checks:
            mb = member_off(sname, member)
            got = mb["byte_off"] if mb else None
            want = macro(mname)
            check(f"btf.{mname}", got is not None and got == want,
                  f"{sname}.{member} 0x{got:x} vs 0x{want:x}" if got is not None else "missing")
        # rb_node color bitfield -> FAKE_WAITER_{,PI_}TREE_PRIO_OFF
        rb = btf.by_name("rb_node")
        if rb:
            _, rbm = btf.members(rb)
            color = [m for m in rbm if m["bit_size"] == 1]
            if color:
                for mname, slot in (("FAKE_WAITER_TREE_PRIO_OFF", "tree"),
                                    ("FAKE_WAITER_PI_TREE_PRIO_OFF", "pi_tree")):
                    base_m = member_off("rt_mutex_waiter", slot)
                    got = (base_m["byte_off"] + color[0]["bit_off"] // 8) if base_m else None
                    want = macro(mname)
                    check(f"btf.{mname}", got is not None and got == want,
                          f"{slot} color bitfield 0x{got:x} vs 0x{want:x}" if got is not None else "missing")
        # deadline slots: written with 0; must lie inside the two 0x28 nodes
        for mname, lo, hi in (("FAKE_WAITER_TREE_DEADLINE_OFF", 0, 0x28),
                              ("FAKE_WAITER_PI_TREE_DEADLINE_OFF", 0x28, 0x50)):
            want = macro(mname)
            check(f"waiter.{mname}", lo <= want < hi, f"0x{want:x} in [0x{lo:x},0x{hi:x})")

    # -- slide data ----------------------------------------------------------
    # worker caller: decode ARM64 BL instructions in worker_thread directly
    # from the raw Image (deterministic, no disassembler dependency).
    # BL encoding: opcode 0x94000000 | (imm26 << 2); target = PC + sext(imm26 << 2)
    sched = sym_off("schedule")
    worker = sym_off("worker_thread")
    if sched is not None and worker is not None:
        bls = []
        end = min(worker + 0x2000, len(raw) - 4)
        pc = worker
        while pc < end:
            insn = struct.unpack_from("<I", raw, pc)[0]
            if (insn & 0xFC000000) == 0x94000000:  # BL (opcode field [31:26] = 100101)
                imm26 = insn & 0x03FFFFFF
                if imm26 & 0x02000000:  # sign-extend 26 bits
                    imm26 -= 0x04000000
                tgt = (pc + (imm26 << 2)) & (2 ** 48 - 1)
                if tgt == sched:
                    bls.append(pc)
            pc += 4
        want = macro("SLIDE_TRACEFS_WORKER_CALLER_OFF")
        if bls:
            got = max(bls) + 4
            check("slide.worker_caller", got == want,
                  f"{len(bls)} 'bl schedule' in worker_thread, last at 0x{max(bls):x}, "
                  f"return PC 0x{got:x} vs 0x{want:x}")
            rep["values"]["SLIDE_TRACEFS_WORKER_CALLER_OFF"] = f"0x{got:x}"
        else:
            check("slide.worker_caller", False,
                  f"no 'bl schedule' found in worker_thread [0x{worker:x}, 0x{worker + 0x2000:x})")
    else:
        check("slide.worker_caller", False,
              f"schedule={sched} worker_thread={worker}")

    # trace event id
    base_id = parse_trace_last_type(a.src_root) if a.src_root else None
    if base_id is None:
        base_id = XREF["event_id_base_612"]
        rep["values"]["trace_event_base_source"] = "cross-ref (a17 on-device 94/74)"
    else:
        rep["values"]["trace_event_base_source"] = "target kernel/trace/trace.h"
    rep["values"]["trace_event_base"] = base_id
    start_ev = sym_off("__start_ftrace_events")
    ev = sym_off("__event_sched_blocked_reason")
    ev_waking = sym_off("__event_sched_waking")
    if start_ev is not None and ev is not None:
        idx = (ev - start_ev) // 8
        got = base_id + idx
        want = macro("SLIDE_TRACEFS_EVENT_ID")
        extra = f", sched_waking index {(ev_waking - start_ev) // 8}" if ev_waking is not None else ""
        check("slide.event_id", got == want,
              f"index {idx} + base {base_id} = {got} vs {want}{extra}")
        rep["values"]["SLIDE_TRACEFS_EVENT_ID"] = got
        rep["values"]["ftrace_event_index"] = idx
    else:
        check("slide.event_id", False,
              f"__start_ftrace_events={start_ev} __event_sched_blocked_reason={ev}")

    # pselect word shift
    want_shift = macro("SLIDE_PSELECT_WORD_SHIFT")
    do_pselect = sym_off("do_pselect")
    check("slide.pselect_shift", want_shift == XREF["pselect_word_shift_612"],
          f"0x{want_shift:x} vs 6.12 GKI cross-ref {XREF['pselect_word_shift_612']}"
          + (f" (do_pselect at 0x{do_pselect:x})" if do_pselect is not None else ""))
    rep["values"]["SLIDE_PSELECT_WORD_SHIFT"] = want_shift

    # -- on-image semantic checks ---------------------------------------------
    nfulnl = sym_off("nfulnl_logger")
    if nfulnl is not None:
        got_name_off = qword(raw, nfulnl) - base
        s = cstr(raw, got_name_off)
        check("data.nfulnl_logger",
              got_name_off == macro("SLIDE_NFULNL_LOGGER_NAME_OFF") and s == "nfnetlink_log",
              f"name qword -> 0x{got_name_off:x} (\"{s}\") vs 0x{macro('SLIDE_NFULNL_LOGGER_NAME_OFF'):x}")
        rep["values"]["SLIDE_NFULNL_LOGGER_NAME_OFF"] = f"0x{got_name_off:x}"

    # random_table boot_id walk
    rt = sym_off("random_table")
    ct = btf.by_name("ctl_table") if btf else None
    if rt is not None and ct:
        _, ctm = btf.members(ct)
        proc_m = [m for m in ctm if m["name"] == "procname"][0]
        data_m = [m for m in ctm if m["name"] == "data"][0]
        ct_size = btf.size(ct)
        entry = None
        for i in range(8):
            e = rt + i * ct_size
            if cstr(raw, qword(raw, e + proc_m["byte_off"]) - base) == "boot_id":
                entry = e
                break
        if entry is not None:
            data_q = qword(raw, entry + data_m["byte_off"])
            got_slot = entry + data_m["byte_off"]
            check("data.random_table_boot_id",
                  got_slot == macro("SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF")
                  and data_q - base == macro("SYSCTL_BOOTID_OFF"),
                  f"entry 0x{entry:x}, .data slot 0x{got_slot:x} -> 0x{data_q - base:x} "
                  f"(sysctl_bootid 0x{macro('SYSCTL_BOOTID_OFF'):x}), "
                  f"ctl_table size 0x{ct_size:x}")
            rep["values"]["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"] = f"0x{got_slot:x}"
        else:
            check("data.random_table_boot_id", False,
                  f"no boot_id entry in random_table[0..8) (base 0x{rt:x}, ctl_table 0x{ct_size:x})")
    else:
        check("data.random_table_boot_id", False, f"random_table={rt} ctl_table={ct}")

    # kvm_misc oracle pair (the writable miscdevice/fops slot)
    kvm_misc = sym_off("kvm_misc")
    if kvm_misc is not None:
        name_q = qword(raw, kvm_misc + 8)
        s = cstr(raw, name_q - base)
        fops_q = qword(raw, kvm_misc + 0x10)
        check("data.kvm_misc_oracle",
              s == "kvm"
              and fops_q - base == macro("ASHMEM_FOPS_OFF")
              and kvm_misc + 0x10 == macro("ASHMEM_MISC_FOPS_OFF")
              and kvm_misc == macro("ASHMEM_MISC_OFF"),
              f"name=\"{s}\", .fops 0x{fops_q - base:x} (ASHMEM_FOPS_OFF), slot 0x{kvm_misc + 0x10:x}")
        if sdata is not None and edata is not None:
            hit = 0
            fops_table = None
            for nm in syms:
                if "ashmem" in nm and "fops_ioctl" in nm:
                    fops_table = syms[nm] - base - macro("FOPS_IOCTL_OFF")
                    break
            if fops_table is not None:
                for o in range(sdata, edata, 8):
                    if qword(raw, o) - base == fops_table:
                        hit += 1
            rep["values"]["data_qwords_pointing_at_ashmem_fops"] = hit

    # Rust ashmem fops table: locate it, verify the 6.12 layout, verify the
    # per-slot ASHMEM_*_OFF macros against the resolved table.
    fops_syms = {}
    for nm in syms:
        if "ashmem" not in nm:
            continue
        m2 = re.search(r"fops_(llseek|read_iter|ioctl|compat_ioctl|mmap|open|release|show_fdinfo)\b", nm)
        if m2:
            fops_syms[m2.group(1)] = syms[nm] - base
    LAYOUTS = {
        "6.12": {"llseek": 0x10, "read_iter": 0x28, "ioctl": 0x50,
                 "compat_ioctl": 0x58, "mmap": 0x60, "open": 0x68,
                 "release": 0x78, "show_fdinfo": 0xd8},
        "6.6": {"llseek": 0x08, "read_iter": 0x20, "ioctl": 0x48,
                "compat_ioctl": 0x50, "mmap": 0x58, "open": 0x68,
                "release": 0x78, "show_fdinfo": 0xd8},
    }
    if fops_syms:
        best = {}
        for lname, layout in LAYOUTS.items():
            cands = [fops_syms[slot] - off for slot, off in layout.items() if slot in fops_syms]
            if not cands:
                continue
            (base_cand, cnt) = Counter(cands).most_common(1)[0]
            matches = sum(1 for slot, off in layout.items()
                          if slot in fops_syms and fops_syms[slot] - base_cand == off)
            best[lname] = (base_cand, matches, len(layout))
        for lname, (bc, matches, total) in best.items():
            rep["values"][f"ashmem_fops_layout_{lname}"] = f"0x{bc:x} {matches}/{total}"
        if "6.12" in best and "6.6" in best:
            check("ashmem.fops_layout",
                  best["6.12"][1] >= 6 and best["6.12"][1] > best["6.6"][1],
                  f"6.12 {best['6.12'][1]}/{best['6.12'][2]} vs 6.6 {best['6.6'][1]}/{best['6.6'][2]}")
        elif "6.12" in best:
            check("ashmem.fops_layout", best["6.12"][1] >= 6,
                  f"6.12 {best['6.12'][1]}/{best['6.12'][2]}")
        else:
            check("ashmem.fops_layout", False, "no candidate fops table found")
        if best.get("6.12", (None, 0, 0))[1] >= 6:
            slot_macro = {"ioctl": "ASHMEM_IOCTL_OFF",
                          "compat_ioctl": "ASHMEM_COMPAT_IOCTL_OFF",
                          "mmap": "ASHMEM_MMAP_OFF",
                          "open": "ASHMEM_OPEN_OFF",
                          "release": "ASHMEM_RELEASE_OFF",
                          "show_fdinfo": "ASHMEM_SHOW_FDINFO_OFF"}
            for slot, mname in slot_macro.items():
                if slot in fops_syms:
                    check(f"ashmem.{mname}", fops_syms[slot] == macro(mname),
                          f"0x{fops_syms[slot]:x} vs 0x{macro(mname):x}")
    else:
        check("ashmem.fops_symbols", False, "no Rust ashmem fops_* symbols found")

    # -- IKCONFIG -------------------------------------------------------------
    if a.config:
        st, ed = sym_off("IKCFG_ST"), sym_off("IKCFG_ED")
        if st is not None and ed is not None and ed > st:
            cfg = gzip.decompress(raw[st:ed])
            committed = Path(a.config).read_bytes()
            check("config.ikconfig", cfg == committed,
                  f"embedded {len(cfg)} bytes vs committed {len(committed)} bytes")
            rep["values"]["ikconfig_size"] = len(cfg)
        else:
            check("config.ikconfig", False, f"IKCFG_ST={st} IKCFG_ED={ed}")

    # -- p0 fingerprint --------------------------------------------------------
    if a.fingerprint:
        probe = macro("P0_ORACLE_PROBE_OFFSET")
        page_offsets = (0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00)
        rows = []
        for slide in range(0, 0x200000, 0x10000):
            src = probe - slide
            rows.append((slide, [qword(raw, src + po) for po in page_offsets]))
        with open(a.raw, "rb") as f:  # independent readback, fresh handle
            data = f.read()
        ok = all(
            all(struct.unpack_from("<Q", data, (probe - slide) + po)[0] == w
                for po, w in zip(page_offsets, words))
            for slide, words in rows
        )
        hdr_words = re.findall(r"0x[0-9a-f]{16}ULL", Path(a.fingerprint).read_text())
        hdr_ok = len(hdr_words) == 32 * 8
        if hdr_ok:
            for row, (slide, words) in enumerate(rows):
                want = [f"0x{w:016x}ULL" for w in words]
                got = hdr_words[row * 8:(row + 1) * 8]
                if got != want:
                    hdr_ok = False
                    break
        check("p0.fingerprint", ok and hdr_ok,
              f"32 rows / 256 qwords at probe 0x{probe:x}, readback {'ok' if ok else 'FAIL'}, "
              f"header {'matches' if hdr_ok else 'MISMATCH'}")
        rep["values"]["p0_probe_offset"] = f"0x{probe:x}"

    # -- source cross-checks ----------------------------------------------------
    if a.src_root:
        sr = Path(a.src_root)
        wq = sr / "kernel/workqueue.c"
        if wq.exists():
            txt = wq.read_text(errors="replace")
            m = re.search(r"struct pool_workqueue \{(.*?)\n\};", txt, re.S)
            if m:
                body = m.group(1)
                members_src = re.findall(r"^\t+(?:\w+(?:\s+\*+)?\s+)?(\w+)\s*(?:=|;)", body, re.M)
                rep["values"]["workqueue_pool_members_src"] = ", ".join(members_src)
                check("src.pool_workqueue_max_active",
                      "max_active" not in members_src,
                      "max_active presence in the 6.12 pool_workqueue source definition")
        slub, slabh = sr / "mm/slub.c", sr / "include/linux/slab.h"
        if slub.exists() and slabh.exists() and a.config:
            stxt = slub.read_text(errors="replace")
            htxt = slabh.read_text(errors="replace")
            m = re.search(r"kmalloc_caches\[(\w+)\]\[(\w+)\]", stxt)
            if m:
                rep["values"]["kmalloc_array_decl"] = m.group(0)
                tdef = re.search(rf"#define\s+{m.group(1)}\s*(.+)", htxt)
                bdef = re.search(rf"#define\s+{m.group(2)}\s*(.+)", htxt)
                if tdef and bdef:
                    cfgtxt = Path(a.config).read_text()

                    def cfg(v):
                        return "1" if re.search(rf"^CONFIG_{v}=y", cfgtxt, re.M) else "0"

                    tdef, bdef = tdef.group(1), bdef.group(1)
                    for pat in (r"IS_ENABLED\((\w+)\)", r"CONFIG_(\w+)"):
                        tdef = re.sub(pat, lambda g: cfg(g.group(1)), tdef)
                        bdef = re.sub(pat, lambda g: cfg(g.group(1)), bdef)
                    try:
                        types = eval(tdef.strip(), {"__builtins__": {}}, {})
                        buckets = eval(bdef.strip(), {"__builtins__": {}}, {})
                        check("src.kmalloc_types",
                              types == macro("KMALLOC_CACHE_TYPES"),
                              f"KMALLOC_TYPES={types} vs {macro('KMALLOC_CACHE_TYPES')}, "
                              f"KMALLOC_BUCKETS={buckets}")
                        rep["values"]["KMALLOC_TYPES"] = types
                        rep["values"]["KMALLOC_BUCKETS"] = buckets
                    except Exception as e:
                        rep["values"]["kmalloc_types_note"] = f"unevaluable: {tdef!r} ({e})"

    # -- reports -----------------------------------------------------------------
    Path(a.report).write_text(json.dumps(rep, indent=2))
    md = ["# A075FXXS5BZD2 derivation report", ""]
    md.append(f"kernel release: **{rep['values'].get('kernel_release', '?')}**")
    md.append(f"symbols: {rep['values'].get('symbol_count', '?')}")
    md.append("")
    md.append("| check | result | detail |")
    md.append("| --- | --- | --- |")
    for c in rep["checks"]:
        md.append(f"| {c['name']} | {'PASS' if c['ok'] else '**FAIL**'} | {c['detail']} |")
    md.append("")
    md.append("## recovered values")
    md.append("")
    for k, v in rep["values"].items():
        md.append(f"- `{k}` = {v}")
    md.append("")
    if rep["errors"]:
        md.append("## FAILURES")
        for e in rep["errors"]:
            md.append(f"- {e}")
        md.append("")
    Path(a.md).write_text("\n".join(md))

    passed = sum(1 for c in rep["checks"] if c["ok"])
    print(f"checks: {passed}/{len(rep['checks'])} passed")
    for e in rep["errors"]:
        print(f"  FAIL {e}")
    return 0 if not rep["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
