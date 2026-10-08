"""Offline tests for A07 image derivation, against a synthetic AArch64 kernel image.

The fixture is a real ELF64 file with a `PT_LOAD` segment, `.text`/`.rodata`/`.data`/
`.data..ro_after_init`/`.bss` sections and a symbol table, laid out the way the derivations expect
a kernel image to be: a `nfulnl_logger` whose `name` points at `"nfnetlink_log"`, a `random_table`
whose `boot_id` entry's `.data` points into `.bss`, an ashmem `file_operations` whose `ioctl` slot
points at `ashmem_memfd_ioctl`, and a read-only-after-init SELinux bool. Every assertion is about a
value read back out of the image, so a derivation that starts assuming instead of reading fails here.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from tools.a07_elf import ElfError, ElfImage
import dataclasses

from tools.derive_a07_image import (
    derive_ashmem,
    source_excerpts,
    derive_selinux,
    derive_slab,
    derive_slide_chain,
    derive_workqueue,
    section_kind,
    writable,
    writability,
)

BASE = 0xFFFFFFC008000000
FOPS = {
    "owner": 0x00, "llseek": 0x08, "read": 0x10, "write": 0x18, "read_iter": 0x20,
    "unlocked_ioctl": 0x30, "compat_ioctl": 0x38, "mmap": 0x40, "open": 0x48,
    "release": 0x50, "show_fdinfo": 0x60,
}
FOPS_SIZE = 0x70
CTL_SIZE = 0x30
RAWS = {"selinux_state": "struct selinux_state {\n\tbool enforcing; /* 8 1 */\n};\n"}

LAYOUTS = {
    "nf_logger": {"list": 0x00, "name": 0x10, "me": 0x18},
    "ctl_table": {"procname": 0x00, "data": 0x08, "maxlen": 0x18, "mode": 0x1C},
    "file_operations": FOPS,
    "slab": {"__page_flags": 0x00, "__page_refcount": 0x34, "__page_type": 0x38, "slab_cache": 0x08},
    "page": {"flags": 0x00, "_refcount": 0x34, "page_type": 0x38, "compound_head": 0x08},
    "pool_workqueue": {"wq": 0x00, "refcnt": 0x10, "nr_active": 0x18},
    "workqueue_struct": {"max_active": 0xA4, "dfl_pwq": 0x20},
    "selinux_state": {"enforcing": 0x08, "policycap": 0x10},
    "__sizes__": {"ctl_table": CTL_SIZE, "file_operations": FOPS_SIZE, "slab": 0x38, "page": 0x40,
                "selinux_state": 0x40},
}

SYMBOLS = (
    # (name, value offset, size, bind, type, section index)
    ("ashmem_memfd_ioctl", 0x0000, 0x20, 1, 2, 1),
    ("configfs_read_iter", 0x0020, 0x20, 1, 2, 1),
    ("nfulnl_logger", 0x2000, 0x20, 0, 1, 3),
    ("random_table", 0x2100, 0x90, 0, 1, 3),
    ("ashmem_fops", 0x2200, FOPS_SIZE, 0, 1, 3),
    ("selinux_enforcing_boot", 0x2400, 0x01, 1, 1, 4),
    ("selinux_state", 0x2300, 0x40, 0, 1, 3),
    ("selinux_state_ro", 0x2440, 0x40, 0, 1, 4),
)


def put64(blob: bytearray, offset: int, value: int) -> None:
    blob[offset:offset + 8] = struct.pack("<Q", value)


def build_image(path: Path, *, logger_string: str = "nfnetlink_log") -> None:
    """Write a synthetic AArch64 kernel image with the layout the derivations walk."""
    blob = bytearray(0x2600)
    blob[0x1000:0x1000 + len(logger_string) + 1] = logger_string.encode() + b"\0"
    blob[0x1020:0x1029] = b"boot_id\0"
    blob[0x1040:0x1049] = b"poolsize\0"
    # nfulnl_logger: list head, then the name pointer the leak reads back.
    put64(blob, 0x2000, BASE + 0x2000)
    put64(blob, 0x2008, BASE + 0x2000)
    put64(blob, 0x2010, BASE + 0x1000)
    # random_table: entry 0 is boot_id, entry 1 is poolsize, entry 2 terminates the walk.
    put64(blob, 0x2100, BASE + 0x1020)
    put64(blob, 0x2108, BASE + 0x3000)
    put64(blob, 0x2130, BASE + 0x1040)
    put64(blob, 0x2138, BASE + 0x3100)
    # ashmem_fops: an ioctl slot naming an ashmem handler, and a configfs read_iter.
    put64(blob, 0x2200 + FOPS["unlocked_ioctl"], BASE + 0x0000)
    put64(blob, 0x2200 + FOPS["read_iter"], BASE + 0x0020)
    put64(blob, 0x2200 + FOPS["compat_ioctl"], BASE + 0x0000)
    blob[0x2400] = 1  # selinux_enforcing_boot, read-only after init
    blob[0x2308] = 1  # selinux_state.enforcing, runtime-writable .data
    blob[0x2448] = 1  # same object shape, but placed in .data..ro_after_init

    data_start = 64 + 56
    strings = [b"\0"] + [name.encode() + b"\0" for name, *_ in SYMBOLS]
    strtab = b"".join(strings)
    str_offsets: list[int] = []
    cursor = 0
    for item in strings:
        str_offsets.append(cursor)
        cursor += len(item)
    symtab = bytearray(24)  # index 0 is the null symbol
    for index, (name, value, size, bind, stype, shndx) in enumerate(SYMBOLS, start=1):
        symtab += struct.pack(
            "<IBBHQQ", str_offsets[index], (bind << 4) | stype, 0, shndx, BASE + value, size
        )

    sections = [
        # name, type, addr, offset, size, link, entsize, sh_flags
        ("", 0, 0, 0, 0, 0, 0, 0),
        (".text", 1, BASE + 0x0000, data_start + 0x0000, 0x1000, 0, 0, 0x6),
        (".rodata", 1, BASE + 0x1000, data_start + 0x1000, 0x1000, 0, 0, 0x2),
        (".data", 1, BASE + 0x2000, data_start + 0x2000, 0x0400, 0, 0, 0x3),
        # __ro_after_init storage is SHF_WRITE in the ELF: only its name says it is read-only later.
        (".data..ro_after_init", 1, BASE + 0x2400, data_start + 0x2400, 0x0100, 0, 0, 0x3),
        (".bss", 8, BASE + 0x3000, 0, 0x1000, 0, 0, 0x3),
    ]
    symtab_offset = data_start + len(blob)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    section_names = [name.encode() + b"\0" for name, *_ in sections] + [
        b".symtab\0", b".strtab\0", b".shstrtab\0"
    ]
    sections += [
        (".symtab", 2, 0, symtab_offset, len(symtab), 7, 24, 0),
        (".strtab", 3, 0, strtab_offset, len(strtab), 0, 0, 0),
        (".shstrtab", 3, 0, shstrtab_offset, sum(len(n) for n in section_names), 0, 0, 0),
    ]
    shstrtab = b"".join(section_names)
    shstr_offsets: list[int] = []
    cursor = 0
    for name in section_names:
        shstr_offsets.append(cursor)
        cursor += len(name)

    shoff = shstrtab_offset + len(shstrtab)
    shoff += (-shoff) % 8
    shstrndx = [name for name, *_ in sections].index(".shstrtab")
    out = bytearray(64)
    out[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
    # e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, 2, 0xB7, 1, BASE, 64, shoff, 0,
                     64, 56, 1, 64, len(sections), shstrndx)
    out[64:64 + 56] = struct.pack("<IIQQQQQQ", 1, 7, data_start, BASE, BASE, len(blob),
                                  0x4000, 0x1000)
    body = bytes(out) + bytes(blob) + bytes(symtab) + strtab + shstrtab
    body += b"\0" * (shoff - len(body))
    shdr = bytearray()
    for index, (name, stype, addr, offset, size, link, entsize, flags) in enumerate(sections):
        shdr += struct.pack("<IIQQQQIIQQ", shstr_offsets[index], stype, flags, addr,
                            offset, size, link, 0, 8 if addr else 1, entsize)
    path.write_bytes(body + bytes(shdr))


class ImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.image_path = cls.root / "kernel.elf"
        build_image(cls.image_path)
        cls.image = ElfImage(cls.image_path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_reader_basics(self):
        self.assertEqual(0xB7, self.image.machine)
        self.assertEqual(BASE + 0x2000, self.image.symbol("nfulnl_logger").value)
        self.assertEqual("nfnetlink_log", self.image.cstring(BASE + 0x1000))
        self.assertEqual(BASE + 0x3000, self.image.pointer(BASE + 0x2108))
        self.assertEqual(".data", section_kind(self.image, BASE + 0x2000))
        self.assertEqual(".data..ro_after_init", section_kind(self.image, BASE + 0x2400))
        self.assertEqual(".bss", section_kind(self.image, BASE + 0x3000))
        self.assertIsNone(self.image.read(BASE + 0x3000, 8), ".bss has no file-backed bytes")
        self.assertEqual("ashmem_memfd_ioctl", self.image.symbol_at(BASE + 0x0000))
        self.assertEqual("nfulnl_logger+0x10", self.image.symbol_at(BASE + 0x2010))
        self.assertTrue(writable(".data"))
        self.assertFalse(writable(".data..ro_after_init"))
        self.assertFalse(writable(".rodata"))

    def test_rejects_non_aarch64_image(self):
        other = self.root / "x86.elf"
        raw = bytearray(self.image_path.read_bytes())
        struct.pack_into("<H", raw, 18, 0x3E)
        other.write_bytes(bytes(raw))
        with self.assertRaisesRegex(ElfError, "not AArch64"):
            ElfImage(other)

    def test_slide_chain_is_derived_and_verified(self):
        slide = derive_slide_chain(self.image, LAYOUTS, BASE)
        self.assertEqual(0x2000, slide["SLIDE_NFULNL_LOGGER_OBJECT_OFF"]["value"])
        self.assertEqual(0x1000, slide["SLIDE_NFULNL_LOGGER_NAME_OFF"]["value"])
        self.assertEqual("derived", slide["SLIDE_NFULNL_LOGGER_NAME_OFF"]["status"])
        self.assertEqual(0x2108, slide["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"]["value"])
        self.assertEqual(0x3000, slide["SLIDE_SYSCTL_BOOTID_OFF"]["value"])
        self.assertEqual(".bss", slide["SLIDE_SYSCTL_BOOTID_OFF"]["section"])
        self.assertIn('procname "boot_id"', slide["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF"]["evidence"])

    def test_slide_chain_refuses_a_wrong_string(self):
        wrong = self.root / "wrong-string.elf"
        build_image(wrong, logger_string="nfnetlink_lie")
        slide = derive_slide_chain(ElfImage(wrong), LAYOUTS, BASE)
        self.assertEqual("cross-check-failed", slide["SLIDE_NFULNL_LOGGER_NAME_OFF"]["status"])
        self.assertIsNone(slide["SLIDE_NFULNL_LOGGER_NAME_OFF"]["value"])

    def test_slide_chain_refuses_a_readonly_scratch_object(self):
        moved = self.root / "readonly-logger.elf"
        build_image(moved)
        image = ElfImage(moved)
        original = image.symbol
        image.symbol = lambda name: (
            type(image.symbol("random_table"))("nfulnl_logger", BASE + 0x2400, 0x20, 0, 1, 4)
            if name == "nfulnl_logger" else original(name)
        )
        slide = derive_slide_chain(image, LAYOUTS, BASE)
        # A read-only scratch object is not a failed cross-check, it is an unusable primitive.
        self.assertEqual("incompatible-section", slide["SLIDE_NFULNL_LOGGER_OBJECT_OFF"]["status"])
        self.assertIsNone(slide["SLIDE_NFULNL_LOGGER_OBJECT_OFF"]["value"])
        self.assertEqual(".data..ro_after_init", slide["SLIDE_NFULNL_LOGGER_OBJECT_OFF"]["section"])

    def test_ashmem_census_and_fops_discovery(self):
        facts = derive_ashmem(self.image, LAYOUTS, BASE)
        names = [item["name"] for item in facts["symbols"]]
        self.assertIn("ashmem_memfd_ioctl", names)
        self.assertIn("ashmem_fops", names)
        candidates = {c["object"]: c for c in facts["fopsCandidates"]}
        self.assertIn("ashmem_fops", candidates)
        self.assertEqual("ashmem_memfd_ioctl", candidates["ashmem_fops"]["ashmemHandlers"]["unlocked_ioctl"])
        self.assertEqual("configfs_read_iter", candidates["ashmem_fops"]["allHandlers"]["read_iter"])
        self.assertEqual(0x2200, candidates["ashmem_fops"]["imageOffset"])

    def test_selinux_readonly_after_init_is_not_writable(self):
        facts = derive_selinux(self.image, LAYOUTS, LAYOUTS["__sizes__"], RAWS, BASE)
        candidate = next(c for c in facts["candidates"] if c["name"] == "selinux_enforcing_boot")
        self.assertEqual(".data..ro_after_init", candidate["section"])
        self.assertFalse(candidate["writable"])
        self.assertEqual(0x2400, candidate["imageOffset"])

    def test_selinux_enforcing_is_derived_from_selinux_state(self):
        facts = derive_selinux(self.image, LAYOUTS, LAYOUTS["__sizes__"], RAWS, BASE)
        derived = facts["derivedEnforcing"]
        self.assertEqual("derived", derived["status"])
        self.assertEqual(0x2308, derived["value"])
        self.assertEqual(".data", derived["section"])
        self.assertEqual(8, derived["enforcingMemberOffset"])
        self.assertEqual(1, derived["byteInImage"])

    def test_source_excerpts_quote_the_decisive_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver = root / "drivers" / "staging" / "android"
            driver.mkdir(parents=True)
            (driver / "ashmem_rust_exports.c").write_text(
                "#include <linux/fs.h>\n"
                "/* filler */\n" * 3
                + "long ashmem_memfd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)\n"
                "{\n\tstruct ashmem_area *area = memfd_ashmem_area(file);\n"
                + "\treturn 0;\n}\n"
            )
            (root / "mm" / "slab.h").parent.mkdir(parents=True, exist_ok=True)
            (root / "mm" / "slab.h").write_text(
                "struct slab {\n\tstruct page __page;\n\tstruct kmem_cache *slab_cache;\n};\n"
            )
            quotes = source_excerpts(root)
            body = " ".join(quotes["ashmem_memfd_ioctl body"])
            self.assertIn("ashmem_rust_exports.c", body)
            self.assertIn("memfd_ashmem_area(file)", body)
            self.assertIn("struct slab {", " ".join(quotes["struct slab definition"]))
            self.assertEqual([], quotes["selinux_state struct"], "an absent file yields no quote")

    def test_writability_uses_names_then_elf_flags(self):
        moved = self.root / "writability.elf"
        build_image(moved)
        image = ElfImage(moved)
        self.assertTrue(writability(image, BASE + 0x2000)["writable"], ".data is writable by name")
        ro = writability(image, BASE + 0x2400)
        self.assertFalse(ro["writable"])
        self.assertIn("read-only at runtime", ro["reason"])
        self.assertTrue(ro["segmentFlags"].find("W") >= 0, "PT_LOAD is RWX in the fixture")

        # A07's kernel.elf puts some objects in a section named `.kernel`; the ELF flags decide then.
        sections = list(image.sections)
        index = next(i for i, sec in enumerate(sections) if sec.name == ".data")
        sections[index] = dataclasses.replace(sections[index], name=".kernel")
        image.sections = sections
        fallback = writability(image, BASE + 0x2000)
        self.assertTrue(fallback["writable"])
        self.assertIn("SHF_WRITE", fallback["reason"])
        sections[index] = dataclasses.replace(sections[index], name=".kernel", flags=0x2)
        image.sections = sections
        self.assertFalse(writability(image, BASE + 0x2000)["writable"])

    def test_bss_object_has_no_file_bytes_but_is_writable(self):
        verdict = writability(self.image, BASE + 0x3000)
        self.assertTrue(verdict["nobits"])
        self.assertTrue(verdict["writable"])
        self.assertIsNone(self.image.read(BASE + 0x3000, 1))

    def test_selinux_enforcing_needs_a_writable_object(self):
        # Same member layout, but the global lives in read-only-after-init storage: the exploit
        # cannot flip enforcing at runtime, so no value may be handed to the header.
        moved = self.root / "readonly-selinux.elf"
        build_image(moved)
        ro = ElfImage(moved)
        original = ro.symbol
        ro.symbol = lambda name: (
            type(original("selinux_state_ro"))("selinux_state", BASE + 0x2440, 0x40, 0, 1, 4)
            if name == "selinux_state" else original(name)
        )
        derived = derive_selinux(ro, LAYOUTS, LAYOUTS["__sizes__"], RAWS, BASE)["derivedEnforcing"]
        self.assertEqual("cross-check-failed", derived["status"])
        self.assertIsNone(derived["value"])

    def test_slab_overlay_is_proven_member_by_member(self):
        result = derive_slab(LAYOUTS, LAYOUTS["__sizes__"])
        self.assertEqual("derived", result["status"])
        self.assertEqual(0x08, result["value"])
        broken = {**LAYOUTS, "slab": {**LAYOUTS["slab"], "__page_type": 0x40}}
        self.assertEqual("cross-check-failed", derive_slab(broken, LAYOUTS["__sizes__"])["status"])
        self.assertIsNone(derive_slab(broken, LAYOUTS["__sizes__"])["value"])

    def test_workqueue_max_active_is_reported_as_moved(self):
        result = derive_workqueue(LAYOUTS)
        self.assertEqual("derived", result["status"])
        self.assertFalse(result["pwqHasMaxActive"])
        self.assertEqual(0xA4, result["wqMaxActiveOffset"])
        self.assertEqual(0x00, result["pwqWqOffset"])


if __name__ == "__main__":
    unittest.main()
