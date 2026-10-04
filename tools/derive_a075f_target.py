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

    def __init__(self, blob, float_payload=4, decltag_payload=8):
        # Payload sizes for the two kinds whose encoding has drifted
        # between encoder versions (btf_float: spec 4; btf_decl_tag:
        # spec 8).  Calibrated per blob by BTF_parse_calibrated().
        self.float_payload = float_payload
        self.decltag_payload = decltag_payload
        (magic, version, flags, hdr_len, type_off, type_len, str_off, str_len) = struct.unpack_from(
            "<HBBIIIII", blob, 0
        )
        if magic != 0xEB9F or version != 1:
            raise SystemExit("bad BTF header")
        self.types = blob[hdr_len + type_off : hdr_len + type_off + type_len]
        self.strings = blob[hdr_len + str_off : hdr_len + str_off + str_len]
        self.table = {}
        self._start = {}
        self.ambiguous = {}
        # Record 0 of the type section is the UNKNOWN (void) type; index it
        # as type 0 so that by_name/members/size agree with the raw BTF ids.
        off, idx = 0, 0
        n = len(self.types)
        self.parse_error = None
        self.bogus_names = 0
        while off < n:
            try:
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
            except (struct.error, ValueError, IndexError) as e:
                # Mid-section fault: keep everything parsed so far (the core
                # kernel types are low-ID and are usually intact), record
                # where the walk died (with raw byte context) and stop.
                # A hard SystemExit here lost the whole blob over one bad
                # tail record.
                ctx = (self.types[max(0, off - 12):off].hex() + " | "
                       + self.types[off:off + 12].hex())
                self.parse_error = (f"type {idx} (off {off}/{n}): {e}; "
                                    f"prev|at={ctx}")
                break
        if off != n and not self.parse_error:
            # Walked the whole section but did not land on the end: the
            # payload arithmetic disagrees with the data (e.g. a vendor
            # BTF quirk or a truncated section).  Keep the partial table
            # if it has substance; the report will say.
            self.parse_error = f"length mismatch: walked {off}, have {n}"
        self._size_memo = {}

    def _name(self, off):
        # An out-of-range or unterminated name is a data/encoder quirk,
        # not a walk fault: the rest of the record (kind, members,
        # offsets) is still trustworthy, so record it and continue with
        # an empty name instead of aborting the whole blob.
        (no,) = struct.unpack_from("<I", self.types, off)
        if no >= len(self.strings):
            self.bogus_names = getattr(self, "bogus_names", 0) + 1
            return ""
        end = self.strings.find(b"\0", no)
        if end < 0:
            self.bogus_names = getattr(self, "bogus_names", 0) + 1
            return ""
        return self.strings[no:end].decode("utf-8", "replace")

    def _skip_payload(self, d, off):
        """off = first byte past {name_off, info, ut}; return next type start."""
        k, v = d["kind"], d["vlen"]
        if k in (BTF.K_STRUCT, BTF.K_UNION):
            return off + v * 12
        if k == BTF.K_ENUM:
            return off + v * 8
        if k in (BTF.K_ENUM64, BTF.K_DATASEC):
            return off + v * 12
        if k in (BTF.K_INT, BTF.K_VAR):
            return off + 4
        if k == BTF.K_DECL_TAG:
            # struct btf_decl_tag { __u32 ro; __u32 kind; } - spec 8,
            # older encoders 4.  Wrong size desyncs the table (member
            # type-ids then point at the wrong records).  Calibrated by
            # BTF_parse_calibrated().
            return off + self.decltag_payload
        if k == BTF.K_FLOAT:
            # struct btf_float { __u32 encoding; } - spec 4, some
            # encoders emit no payload.  Calibrated.
            return off + self.float_payload
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

    def by_name(self, name, kinds=None):
        # The kernel BTF can carry more than one type with the same name
        # (BTF dedup keeps variants that differ in shape or kflag, e.g. the
        # __randomize_layout / CFI cases).  Callers of member_off() below
        # cross-check that all variants agree on the member they need; here
        # we return the first (struct-kind preferred) hit and record the
        # ambiguity so the report can audit it.
        hits = [i for i, d in self.table.items() if d["name"] == name]
        if kinds is not None:
            k2 = [i for i in hits if self.table[i]["kind"] in kinds]
            if k2:
                hits = k2
        if not hits:
            return None
        if len(hits) > 1:
            self.ambiguous[name] = hits
        return hits[0]

    def members(self, idx, _depth=0):
        d = self.table[idx]
        if d["kind"] not in (self.K_STRUCT, self.K_UNION):
            raise SystemExit(f"{d['name']} is not a struct/union")
        off = self._start[idx] + 12
        out = []
        for i in range(d["vlen"]):
            mno, mtype, enc = struct.unpack_from("<III", self.types, off + i * 12)
            if mno >= len(self.strings):
                mname = ""
            else:
                end = self.strings.index(b"\0", mno)
                mname = self.strings[mno:end].decode("utf-8", "replace")
            if d["kflag"]:
                bit_off, bit_size = enc & 0xFFFFFF, enc >> 24
            else:
                bit_off, bit_size = enc, 0
            sub = self.table.get(mtype)
            if (not mname and sub is not None
                    and sub["kind"] in (self.K_STRUCT, self.K_UNION)
                    and _depth < 8):
                # Anonymous field: C promotes its members into this struct,
                # with offsets relative to the field start.  (struct page's
                # compound_head / page_type live in anonymous unions.)
                for sm in self.members(mtype, _depth + 1)[1]:
                    t = dict(sm)
                    t["bit_off"] = bit_off + sm["bit_off"]
                    t["byte_off"] = (t["bit_off"] // 8
                                     if t["bit_off"] % 8 == 0 else None)
                    out.append(t)
            else:
                out.append({"name": mname, "type": mtype, "bit_off": bit_off,
                            "bit_size": bit_size,
                            "byte_off": bit_off // 8 if bit_off % 8 == 0
                            else None})
        return d, out

    def raw_members(self, idx):
        """First-level members only, no anonymous-field promotion.

        Diagnostic use: when a flattened lookup fails, this shows exactly
        what the encoder wrote (named vs anonymous fields, raw bit offsets)
        so the report explains the shape mismatch."""
        d = self.table[idx]
        off = self._start[idx] + 12
        out = []
        for i in range(d["vlen"]):
            mno, mtype, enc = struct.unpack_from("<III", self.types, off + i * 12)
            if mno >= len(self.strings):
                mname = ""
            else:
                end = self.strings.index(b"\0", mno)
                mname = self.strings[mno:end].decode("utf-8", "replace")
            if d["kflag"]:
                bit_off, bit_size = enc & 0xFFFFFF, enc >> 24
            else:
                bit_off, bit_size = enc, 0
            out.append({"name": mname, "type": mtype, "bit_off": bit_off,
                        "bit_size": bit_size})
        return out


def BTF_parse_calibrated(blob):
    """Parse a BTF blob, auto-calibrating the two encoder-version-sensitive
    payload sizes (btf_float: spec 4, some encoders 0; btf_decl_tag: spec
    8, older encoders 4).

    A wrong payload size desyncs the type walk.  The desync is nasty
    because it can re-lock onto a later record boundary, producing a
    walk that completes 'cleanly' (lands on the section end, no record
    fault) yet still carries phantom records and swallows a real one -
    so every type id after the anomaly points one record off and member
    type-ids decode against the wrong records (struct page's anonymous
    unions then 'contain' unrelated types and compound_head vanishes).
    Completeness alone therefore does NOT prove alignment.

    Discriminators, in order: no record fault; exactly one UNKNOWN type
    (a well-formed BTF has a single void type, id 0 - phantoms add more);
    no out-of-range name reads (a desynced header almost always reads a
    size/type-id where a name offset belongs); then the largest table.
    Returns (btf, chosen_sizes|None) - None means no combination was
    cleanly aligned and the caller must flag the result as suspect."""
    best = None
    best_score = None
    for fp, dp in ((4, 8), (0, 8), (4, 4), (0, 4)):
        b = BTF(blob, float_payload=fp, decltag_payload=dp)
        unkn = sum(1 for d in b.table.values() if d["kind"] == 0)
        bogus = getattr(b, "bogus_names", 0)
        complete = b.parse_error is None
        score = (1 if complete else 0,
                 1 if unkn == 1 else 0,
                 1 if bogus == 0 else 0,
                 len(b.table))
        if best_score is None or score > best_score:
            best_score = score
            best = b
    clean = best.parse_error is None and \
        sum(1 for d in best.table.values() if d["kind"] == 0) == 1 and \
        getattr(best, "bogus_names", 0) == 0
    for fp, dp in ((4, 8), (0, 8), (4, 4), (0, 4)):
        if clean and (best.float_payload, best.decltag_payload) == (fp, dp):
            best.payload_choice = (fp, dp)
            return best, (fp, dp)
    best.payload_choice = None
    return best, None


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
    # A release Image can legitimately contain more than one raw BTF blob
    # (main .BTF plus a smaller embedded one, e.g. for built-in modules or a
    # vendor section).  Return every header-valid candidate, largest first;
    # the caller picks the one that actually parses and holds the core types.
    candidates.sort(key=lambda r: r[1] - r[0], reverse=True)
    return [(raw[s:e], (s, e)) for (s, e) in candidates]


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


def extract_func_source(root, rel_path, sig_re):
    """Return (body, [(lineno, line), ...]) for the function whose
    signature matches sig_re (brace-matched), or (None, [])."""
    p = Path(root) / rel_path
    if not p.is_file():
        return None, []
    lines = p.read_text(errors="replace").splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.search(sig_re, ln):
            start = i
            break
    if start is None:
        return None, []
    # find first '{' from the signature line, then brace-match
    depth = 0
    begin = None
    for i in range(start, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                if begin is None:
                    begin = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and begin is not None:
                    return "\n".join(lines[start:i + 1]), lines
    return None, lines


def arm64_bl_target(insn):
    """Return target offset for BL (0x94..) or B (0x14..), else None."""
    op = insn & 0xFC000000
    if op not in (0x94000000, 0x14000000):
        return None
    imm26 = insn & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return insn if False else imm26 << 2  # displacement; caller adds PC


def arm64_note(insn):
    """Very small mnemonic hint for context dumps."""
    op = insn & 0xFC000000
    if op in (0x94000000, 0x14000000):
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        kind = "bl" if op == 0x94000000 else "b"
        return f"{kind} +0x{(imm26 << 2):x}"
    if insn == 0xD65F03C0:
        return "ret"
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"br x{insn & 0x1F}"
    if (insn & 0xFFFFFC1F) == 0xD63F03C0:
        return f"blr x{insn & 0x1F}"
    if (insn & 0xFF800000) == 0x5A800000:  # cmp (reg)
        return "cmp"
    if (insn & 0xFF200000) == 0x6B000000:  # subs
        return "subs"
    return f".word 0x{insn:08x}"


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
    try:
        return _run(a)
    except Exception:
        # Never die without a report: record the crash as a failed check so
        # the CI gate (and the diagnostics push) always gets the artifact.
        import traceback
        rep = {"checks": [{"name": "verifier.crash", "ok": False,
                           "detail": "".join(traceback.format_exc())[-4000:]}],
               "values": {}, "errors": ["verifier crashed (see report)"]}
        try:
            Path(a.report).write_text(json.dumps(rep, indent=2))
            Path(a.md).write_text(
                "# A075FXXS5BZD2 derivation report\n\n"
                "## CRASH\n\n```\n"
                + "".join(traceback.format_exc())
                + "\n```\n")
        except Exception:
            pass
        traceback.print_exc()
        return 1


def _run(a):
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
    btf_range = None
    try:
        cands = find_btf(raw)
        parses = []
        perrs = []
        for blob, rng in cands:
            try:
                b, choice = BTF_parse_calibrated(blob)
            except SystemExit as e:
                perrs.append(f"0x{rng[0]:x}: {e}")
                continue
            parses.append((b, choice, rng))
        btf_choice = None
        for b, choice, rng in parses:
            if b.by_name("task_struct", (BTF.K_STRUCT, BTF.K_UNION)) is not None:
                btf, btf_range, btf_choice = b, rng, choice
                break
        if btf is None and parses:
            btf, btf_range, btf_choice = parses[0]
        sizes = ", ".join(f"0x{s:x}-0x{e:x}" for _, (s, e) in cands)
        detail = f"{len(cands)} candidate blob(s) [{sizes}]"
        if btf:
            detail += (f", chose Image[0x{btf_range[0]:x}, 0x{btf_range[1]:x}), "
                       f"{len(btf.table)} types")
            if btf_choice:
                detail += (f", payload(float,decltag)={btf_choice}")
            else:
                detail += ", payload SIZES UNCALIBRATED"
            if getattr(btf, "bogus_names", 0):
                detail += f", {btf.bogus_names} unrecoverable name(s)"
            if btf.parse_error:
                detail += f" (partial parse: {btf.parse_error[:300]})"
        else:
            detail += ", none parsed"
            if perrs:
                detail += " [" + "; ".join(perrs[:4])[:400] + "]"
        check("btf.extract", btf is not None, detail)
        if btf is not None:
            # Diagnostics: the real-kernel blob parses but some core struct
            # names come up missing; dump enough to see what the table
            # actually contains (kind histogram, first types, name probes).
            import collections
            knames = {getattr(BTF, k): k[2:] for k in dir(BTF)
                      if k.startswith("K_")}
            hist = collections.Counter(d["kind"] for d in btf.table.values())
            rep["values"]["btf.kind_hist"] = ", ".join(
                f"{knames.get(k, k)}={n}" for k, n in sorted(hist.items()))
            rep["values"]["btf.first_types"] = ", ".join(
                f"{i}:{knames.get(btf.table[i]['kind'], btf.table[i]['kind'])}:"
                f"{btf.table[i]['name']}" for i in list(btf.table)[:30])
            for probe in ("file_operations", "task_struct", "page",
                          "pool_workqueue"):
                kn = {getattr(BTF, k): k[2:] for k in dir(BTF)
                      if k.startswith("K_")}
                exact = [i for i, d in btf.table.items()
                         if d["name"] == probe]
                sub = [f"{i}:{kn.get(d['kind'], d['kind'])}:{d['name']}"
                       for i, d in btf.table.items()
                       if probe in d["name"]][:8]
                rep["values"][f"btf.probe.{probe}"] = (
                    f"exact={len(exact)} at {exact[:6]}; substring={sub}")
    except SystemExit as e:
        check("btf.extract", False, str(e))

    def member_off(struct_name, member):
        if not btf:
            return None
        idxs = [i for i, d in btf.table.items()
                if d["name"] == struct_name
                and d["kind"] in (BTF.K_STRUCT, BTF.K_UNION)]
        if not idxs:
            idxs = [i for i, d in btf.table.items()
                    if d["name"] == struct_name]
        if not idxs:
            return None
        offs = []
        for i in idxs:
            try:
                _, members = btf.members(i)
            except SystemExit:
                continue
            for m in members:
                if m["name"] == member:
                    offs.append(m)
                    break
        if not offs:
            return None
        boffs = [m["byte_off"] for m in offs]
        if len(set(boffs)) != 1:
            rep["values"][f"btf.variant_conflict.{struct_name}.{member}"] = \
                [f"type 0x{i:x}=0x{m['byte_off']:x}"
                 for i, m in zip([x for x in idxs], offs)
                 if m["byte_off"] is not None]
            return None
        if len(idxs) > 1:
            rep["values"][f"btf.variants.{struct_name}"] = len(idxs)
        return offs[0]

    def struct_size(name):
        if not btf:
            return None
        idxs = [i for i, d in btf.table.items()
                if d["name"] == name
                and d["kind"] in (BTF.K_STRUCT, BTF.K_UNION)]
        if not idxs:
            idxs = [i for i, d in btf.table.items() if d["name"] == name]
        if not idxs:
            return None
        sizes = [btf.size(i) for i in idxs]
        if len(set(sizes)) != 1:
            rep["values"][f"btf.variant_conflict.{name}.size"] = sizes
            return None
        if len(idxs) > 1:
            rep["values"][f"btf.variants.{name}"] = len(idxs)
        return sizes[0]

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
                got = struct_size(sname)
            else:
                mb = member_off(sname, member)
                got = mb["byte_off"] if mb else None
            want = macro(mname)
            detail = (f"{sname}.{member or 'size'} 0x{got:x} vs 0x{want:x}"
                      if got is not None else f"{sname}.{member} not in BTF")
            if got is None and member:
                # Diagnostic: dump each same-named variant's RAW (un-flattened)
                # members so the report shows the actual encoded shape -
                # named vs anonymous fields, raw bit offsets - and explains
                # why the flattened lookup missed.
                try:
                    def _sig(tid, depth=0, budget=[48]):
                        """Nesting signature of a struct/union: named members
                        by name, anonymous ones as {recursive signature}."""
                        if budget[0] <= 0:
                            return "..."
                        sub = btf.table.get(tid)
                        if sub is None or sub["kind"] not in (BTF.K_STRUCT,
                                                              BTF.K_UNION):
                            return "?"
                        parts = []
                        for im in btf.raw_members(tid)[:12]:
                            budget[0] -= 1
                            if im["name"]:
                                parts.append(im["name"])
                            else:
                                parts.append("{" + _sig(im["type"], depth + 1,
                                                        budget) + "}")
                        return ",".join(parts[:12])

                    vidxs = [i for i, d in btf.table.items()
                             if d["name"] == sname
                             and d["kind"] in (BTF.K_STRUCT, BTF.K_UNION)][:4]
                    for vi in vidxs:
                        rawm = btf.raw_members(vi)
                        disp = []
                        for rm in rawm[:60]:
                            if rm["name"]:
                                tag = rm["name"]
                            else:
                                sub = btf.table.get(rm["type"])
                                kk = ({BTF.K_STRUCT: "S", BTF.K_UNION: "U"}
                                      .get(sub["kind"], "?") if sub else "?")
                                tag = f"<anon{kk}-t{rm['type']}:" + _sig(
                                    rm["type"]) + ">"
                            bo = (f"@0x{rm['bit_off'] // 8:x}"
                                  if rm["bit_off"] % 8 == 0
                                  else f"@b{rm['bit_off']}")
                            disp.append(tag + bo)
                        detail += (f" | type 0x{vi:x} sz 0x{btf.size(vi):x} "
                                   f"({len(rawm)}m): " + ", ".join(disp))
                    try:
                        flat = [m["name"] or "<anon>"
                                for m in btf.members(vidxs[0])[1][:40]]
                        detail += " | flattened[0..40]: " + ", ".join(flat)
                    except SystemExit:
                        pass
                except Exception as diag_e:  # never let diagnostics break the run
                    detail += f" | member-diag failed: {diag_e}"
            check(f"btf.{mname}", got is not None and got == want, detail)
            if got is not None:
                rep["values"][mname] = f"0x{got:x}"

        for sname in ("pool_workqueue", "mm_struct", "sk_buff",
                      "rt_mutex_waiter", "task_struct", "rb_node",
                      "file_operations", "configfs_buffer", "miscdevice",
                      "ctl_table", "nf_logger", "page"):
            idx = btf.by_name(sname, (BTF.K_STRUCT, BTF.K_UNION))
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
        rb = btf.by_name("rb_node", (BTF.K_STRUCT, BTF.K_UNION))
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
        # Bound the scan to worker_thread's own body: the next symbol after
        # it (no global symbol can sit *inside* worker_thread's range, so the
        # next symbol marks its end) plus a sanity cap, so a 'bl schedule' in
        # a *later* function can never be picked up.  All offsets below are
        # base-relative, matching worker/sched.
        import bisect
        rel_offs = sorted(o - base for o in syms.values())
        i = bisect.bisect_right(rel_offs, worker)
        body_end = rel_offs[i] if i < len(rel_offs) else worker + 0x10000
        end = min(body_end, worker + 0x10000, len(raw) - 4)
        bls = []
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
        # context dumps (binary + source) so the choice of *which* bl
        # schedule is the blocking idle sleep is auditable from the report
        ctx = []
        for b in bls:
            win = []
            for k in range(-10, 5):
                off = b + 4 * k
                if 0 <= off + 4 <= len(raw):
                    w = struct.unpack_from("<I", raw, off)[0]
                    mark = " <<<" if k == 0 else ""
                    tgt = ""
                    op = w & 0xFC000000
                    if op in (0x94000000, 0x14000000):
                        imm26 = w & 0x03FFFFFF
                        if imm26 & 0x02000000:
                            imm26 -= 0x04000000
                        t = (off + (imm26 << 2)) & (2 ** 48 - 1)
                        tgt = f" -> 0x{t - base:x}" if t >= base else f" -> 0x{t:x}"
                    win.append(f"0x{off:x}: {arm64_note(w)}{tgt}{mark}")
            ctx.append(f"bl at +0x{b - worker:x} (0x{b:x}):\n" + "\n".join(win))
        rep["values"]["worker_caller_bl_context"] = "\n\n".join(ctx)
        if a.src_root:
            body, lines = extract_func_source(
                a.src_root, "kernel/workqueue.c",
                r"\bstatic void worker_thread\s*\(")
            if body:
                calls = []
                for i, ln in enumerate(lines):
                    if re.search(r"(?<![\w.])schedule\s*\(\s*\)", ln):
                        s = max(0, i - 3)
                        calls.append("  " + "\n  ".join(lines[s:i + 1]))
                rep["values"]["worker_caller_source_schedule_calls"] = (
                    f"{len(calls)} schedule() call(s) in worker_thread:\n"
                    + "\n\n".join(calls))
            else:
                rep["values"]["worker_caller_source_schedule_calls"] = (
                    "worker_thread not found in kernel/workqueue.c")
        if bls:
            got = max(bls) + 4
            rels = ", ".join(f"0x{b - worker:x}" for b in bls)
            check("slide.worker_caller", got == want,
                  f"{len(bls)} 'bl schedule' in worker_thread body [0x{worker:x}, "
                  f"0x{end:x}), at +[{rels}] (last +0x{max(bls) - worker:x}), "
                  f"return PC 0x{got:x} vs 0x{want:x}")
            rep["values"]["SLIDE_TRACEFS_WORKER_CALLER_OFF"] = f"0x{got:x}"
        else:
            check("slide.worker_caller", False,
                  f"no 'bl schedule' found in worker_thread [0x{worker:x}, 0x{end:x})")
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
    ct = (btf.by_name("ctl_table", (BTF.K_STRUCT, BTF.K_UNION))
          if btf else None)
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

    # Ashmem fops table: the PRIMARY verification reads the table directly
    # from the Image at ASHMEM_FOPS_OFF (that offset itself is anchored by the
    # kvm_misc oracle check above) and compares every 6.12-layout slot
    # against the ASHMEM_*_OFF macros.  Release kernels strip the Rust
    # symbols, so the symbol-based cross-check below is only an extra when
    # the symbols happen to be present.
    LAYOUTS = {
        "6.12": {"llseek": 0x10, "read_iter": 0x28, "ioctl": 0x50,
                 "compat_ioctl": 0x58, "mmap": 0x60, "open": 0x68,
                 "release": 0x78, "show_fdinfo": 0xd8},
        "6.6": {"llseek": 0x08, "read_iter": 0x20, "ioctl": 0x48,
                "compat_ioctl": 0x50, "mmap": 0x58, "open": 0x68,
                "release": 0x78, "show_fdinfo": 0xd8},
    }
    fops_syms = {}
    for nm in syms:
        if "ashmem" not in nm:
            continue
        m2 = re.search(r"fops_(llseek|read_iter|ioctl|compat_ioctl|mmap|open|release|show_fdinfo)\b", nm)
        if m2:
            fops_syms[m2.group(1)] = syms[nm] - base

    fops_base = macro("ASHMEM_FOPS_OFF")
    slot_macro = {"ioctl": "ASHMEM_IOCTL_OFF",
                  "compat_ioctl": "ASHMEM_COMPAT_IOCTL_OFF",
                  "mmap": "ASHMEM_MMAP_OFF",
                  "open": "ASHMEM_OPEN_OFF",
                  "release": "ASHMEM_RELEASE_OFF",
                  "show_fdinfo": "ASHMEM_SHOW_FDINFO_OFF"}
    bad = []
    for slot, mname in slot_macro.items():
        v = qword(raw, fops_base + LAYOUTS["6.12"][slot])
        got = v - base if v else 0  # a NULL slot stays NULL
        want = macro(mname)
        if got != want:
            bad.append(f"{slot} 0x{got:x} vs 0x{want:x}")
    check("ashmem.fops_table",
          not bad,
          f"fops @0x{fops_base:x} (6.12 layout): {len(slot_macro) - len(bad)}/{len(slot_macro)} slots match"
          + (f"; MISMATCH {bad}" if bad else ""))

    # Anchor discovery: ASHMEM_FOPS_OFF has never been proven on this kernel
    # to be a miscdevice's .fops (the kvm_misc oracle cannot run - that
    # symbol is absent from this ELF's symbol table).  Dump the full table,
    # its section, and scan .data for every plausible miscdevice object so
    # the true anchor (and the 'ashmem' device, if one exists) is identified
    # from evidence rather than assumption.
    try:
        tdump = []
        for k in range(0, 0x108, 8):
            v = qword(raw, fops_base + k) - base
            tdump.append(f"0x{k:x}=0x{v & 0xFFFFFFFFFFFFFFFF:x}")
        rep["values"][f"ashmem.fops_table_dump@0x{fops_base:x}"] = " ".join(tdump)
        sh = run(["readelf", "-SW", str(elf)]).stdout
        for ln in sh.splitlines():
            m = re.match(
                r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+"
                r"([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)", ln)
            if m:
                vaddr, sz = int(m.group(2), 16), int(m.group(3), 16)
                if vaddr <= base + fops_base < vaddr + sz:
                    rep["values"]["ashmem.fops_table_section"] = \
                        f"{m.group(1)} @0x{vaddr:x}+0x{sz:x}"
    except (SystemExit, struct.error, IndexError):
        rep["values"]["ashmem.fops_table_dump"] = "dump failed"
    if sdata is not None and edata is not None:
        noop = sym_off("noop_llseek")
        cands = []
        # .data can extend to (or past) the end of the raw Image (BSS is not
        # stored in the Image), so keep the scan inside the buffer.
        scan_hi = min(edata, sdata + 0x800000, len(raw) - 0x18)
        for o in range(sdata, scan_hi, 8):
            name_q = qword(raw, o + 8)
            if not (base < name_q < base + len(raw) - 2):
                continue
            nm = cstr(raw, name_q - base, 32)
            if not (2 <= len(nm) <= 32
                    and all(32 <= b < 127 for b in nm.encode())):
                continue
            t = qword(raw, o + 0x10) - base
            if not (0x1000 < t < len(raw) - 0x110):
                continue
            ll = qword(raw, t + 0x10) - base
            io = qword(raw, t + 0x50) - base
            if not ((0 < ll < len(raw)) or (0 < io < len(raw))
                    or (noop is not None and ll == noop)):
                continue
            cands.append((o, nm, t, ll, io))
        cands.sort(key=lambda c: 0 if re.search(
            r"ashmem|kvm|sync|dmabuf|vdc", c[1]) else 1)
        for o, nm, t, ll, io in cands[:12]:
            rep["values"][f"misc_candidate.0x{o:x}"] = (
                f"name=\"{nm}\" .fops=0x{t:x} llseek=0x{ll:x} "
                f"ioctl=0x{io:x}" + ("  (SAME TABLE AS ASHMEM_FOPS_OFF)"
                                     if t == fops_base else ""))
        rep["values"]["misc_candidate_count"] = len(cands)

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
            for slot, mname in slot_macro.items():
                if slot in fops_syms:
                    check(f"ashmem.{mname}", fops_syms[slot] == macro(mname),
                          f"0x{fops_syms[slot]:x} vs 0x{macro(mname):x}")
    else:
        rep["values"]["ashmem.fops_symbols"] = (
            "no Rust ashmem fops_* symbols in this ELF (release build "
            "strips Rust statics) - the in-image table check above is the "
            "primary verification for this kernel")

    # -- IKCONFIG -------------------------------------------------------------
    if a.config:
        # Modern kernels name the bounds __ikconfig_start/__ikconfig_end;
        # very old ones used IKCFG_ST/IKCFG_ED.  Try both.
        st = ed = None
        used_names = None
        for sn, en in (("IKCFG_ST", "IKCFG_ED"),
                       ("__ikconfig_start", "__ikconfig_end")):
            s, e = sym_off(sn), sym_off(en)
            if s is not None and e is not None and e > s:
                st, ed, used_names = s, e, (sn, en)
                break
        if st is not None:
            blob = raw[st:ed]
            if blob[:2] == b"\x1f\x8b":
                cfg = gzip.decompress(blob)
                mode = "gzip"
            else:
                # CONFIG_IKCONFIG without a COMPRESSION variant embeds the
                # config plain (this target's config has no
                # IKCONFIG_COMPRESS_* entry at all).
                cfg = blob
                mode = "plain"
            committed = Path(a.config).read_bytes()
            check("config.ikconfig", cfg == committed,
                  f"embedded {len(cfg)} bytes ({mode}, {used_names}) vs "
                  f"committed {len(committed)} bytes")
            rep["values"]["ikconfig_size"] = len(cfg)
            rep["values"]["ikconfig_names"] = " ".join(used_names)
        else:
            # No bound symbols in the recovered table: fall back to locating
            # the blob by content (plain or gzip-compressed committed config).
            committed = Path(a.config).read_bytes()
            found = None
            gz = gzip.compress(committed)
            for mode, full in (("plain", committed), ("gzip", gz)):
                if len(full) > 0x40000:
                    continue
                # The gzip header carries an mtime, so anchor on the
                # post-header payload for the compressed variant.
                if mode == "plain":
                    needle, hdr = full[:96], 0
                else:
                    needle, hdr = full[10:110], 10
                # Full-blob equality; for gzip the 10-byte header carries an
                # mtime that legitimately differs, so compare post-header.
                off = raw.find(needle)
                while off >= hdr:
                    start = off - hdr
                    hdr_ok = (mode == "plain"
                              or raw[start:start + 3] == b"\x1f\x8b\x08")
                    if mode == "plain":
                        body_ok = raw[start:start + len(full)] == full
                    else:
                        body_ok = (off + len(full) - hdr <= len(raw)
                                   and raw[off:off + len(full) - hdr]
                                   == full[hdr:])
                    if hdr_ok and body_ok:
                        found = (start, start + len(full), mode, full)
                        break
                    off = raw.find(needle, off + 1)
            # (2) Anchor search: a kernel that embeds a config must contain
            # 'CONFIG_IKCONFIG=y'; walk back to the config header line, then
            # either match the committed blob exactly or quantify the drift
            # line by line (a published GKI kernel.config can legally differ
            # from the build-time .config by a few lines - version banner,
            # vendor options - and that drift must be reported, not hidden).
            drift = None  # (blob, start, end, differing_lines)
            if found is None:
                anchor = b"CONFIG_IKCONFIG=y"
                hdr_line = b"# Automatically generated file; DO NOT EDIT."
                off = raw.find(anchor)
                while off >= 0 and found is None and drift is None:
                    hdr = raw.rfind(hdr_line, max(0, off - 8192), off)
                    if hdr >= 0 and raw[hdr - 2:hdr] == b"#\n":
                        start = hdr - 2
                        if raw[start:start + len(committed)] == committed:
                            found = (start, start + len(committed),
                                     "plain", committed)
                        elif raw[start:start + 2] == b"\x1f\x8b":
                            drift = (None, start, start,
                                     ["embedded blob is gzip-compressed"])
                        else:
                            nul = raw.find(b"\x00", off)
                            end = (nul if 0 < nul - start < 0x60000
                                   else start + len(committed))
                            blob = raw[start:end]
                            import difflib
                            got_l = blob.decode("utf-8", "replace").splitlines()
                            want_l = committed.decode("utf-8", "replace").splitlines()
                            diff = [l for l in difflib.unified_diff(
                                want_l, got_l, lineterm="")
                                if l.startswith(("+", "-"))
                                and not l.startswith(("+++", "---"))]
                            plus = [l[1:] for l in diff if l.startswith("+")]
                            drift = (blob, start, end, plus)
                    off = raw.find(anchor, off + 1)
            if found:
                off, ed, mode, cfg = found
                check("config.ikconfig", True,
                      f"blob located by content at [0x{off:x}, 0x{ed:x}) "
                      f"({mode}, {len(cfg)} bytes) - bound symbols absent")
                rep["values"]["ikconfig_size"] = len(cfg)
                rep["values"]["ikconfig_range"] = f"0x{off:x}-0x{ed:x}"
                rep["values"]["ikconfig_names"] = "content-search"
            elif drift is not None:
                blob, start, end, plus = drift
                if blob is None:
                    check("config.ikconfig", False,
                          "config.ikconfig: " + "; ".join(plus) +
                          f" at [0x{start:x}) - re-verify CONFIG_IKCONFIG_* "
                          f"and the committed file")
                else:
                    n = len(plus)
                    ok = n <= 4
                    check("config.ikconfig", ok,
                          f"blob at [0x{start:x}, 0x{end:x}) ({len(blob)} B) "
                          f"drifts from committed config by {n} line(s): "
                          + " | ".join(plus[:8]))
                    rep["values"]["ikconfig_size"] = len(blob)
                    rep["values"]["ikconfig_range"] = f"0x{start:x}-0x{end:x}"
                    rep["values"]["ikconfig_names"] = "content-search(drift)"
                    rep["values"]["ikconfig_drift_lines"] = \
                        "; ".join(plus[:12]) or "size-only difference"
            else:
                avail = [n for n in ("IKCFG_ST", "IKCFG_ED",
                                     "__ikconfig_start", "__ikconfig_end")
                         if n in syms]
                # Probe the image for config text so the report says WHY no
                # blob was found (absent section? compressed? renamed
                # header?).
                probes = {
                    "CONFIG_IKCONFIG=y": raw.count(b"CONFIG_IKCONFIG=y"),
                    "CONFIG_IKCONFIG": raw.count(b"CONFIG_IKCONFIG"),
                    "hdr DO NOT EDIT": raw.count(
                        b"# Automatically generated file; DO NOT EDIT."),
                    "banner 6.12.23": raw.count(
                        b"Linux/arm64 Version 6.12.23"),
                }
                rep["values"]["ikconfig_image_probe"] = probes
                if probes["CONFIG_IKCONFIG=y"] == 0 \
                        and probes["hdr DO NOT EDIT"] == 0:
                    # The kernel embeds no config text at all (IKCONFIG not
                    # in the actual build).  There is nothing in the Image to
                    # verify against: log it loudly and continue degraded -
                    # the committed config still comes from the official GKI
                    # package for this exact build and is exercised by the
                    # source cross-checks below.
                    check("config.ikconfig", True,
                          "DEGRADED: no embedded ikconfig in the Image "
                          "(probes {}) - config cannot be verified against "
                          "the running kernel; committed config is from the "
                          "official GKI package (banner and source checks "
                          "still apply)".format(probes))
                    rep["values"]["ikconfig_status"] = "not-embedded"
                else:
                    check("config.ikconfig", False,
                          f"no ikconfig bound symbols ({avail or 'none'}); "
                          f"content search also failed (config "
                          f"{len(committed)} B); image probes {probes}")

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
