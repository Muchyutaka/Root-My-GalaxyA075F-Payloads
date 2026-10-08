#!/usr/bin/env python3
"""Read-only ELF64 image access for deriving SM-A075F kernel facts.

The A07 port needs three things from `kernel.elf`: its symbol table, the mapping from a kernel
virtual address to image bytes, and the bytes themselves (initialised pointers, strings, structure
contents). binutils prints text, which is fine for names but cannot answer "what pointer is stored
at this address" without another parsing layer, so the image is read directly here. Every value a
derivation reports then comes from the same file whose SHA-256 the release verifier already checked.

Only `PT_LOAD`-backed bytes can be read. `.bss` contents are not in the file, so a pointer into
`.bss` reads as absent rather than as zero - which is the honest answer for an unbooted image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

PT_LOAD = 1
SHT_NOBITS = 8
SHT_SYMTAB = 2
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
SHT_STRTAB = 3
SHT_DYNSYM = 11

STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS"}
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2


@dataclass(frozen=True)
class Section:
    name: str
    type: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int
    flags: int = 0

    @property
    def nobits(self) -> bool:
        return self.type == SHT_NOBITS

    @property
    def shf_write(self) -> bool:
        return bool(self.flags & SHF_WRITE)


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    bind: str
    type: str
    shndx: int

    @property
    def defined(self) -> bool:
        return self.shndx not in (SHN_UNDEF, SHN_COMMON)


@dataclass(frozen=True)
class Segment:
    type: int
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int


class ElfError(RuntimeError):
    pass


class ElfImage:
    """An ELF64 little-endian image: sections, symbols, and VA-addressed bytes."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise ElfError(f"{self.path.name} is not an ELF file")
        if self.data[4] != 2:
            raise ElfError(f"{self.path.name} is not ELF64")
        if self.data[5] != 1:
            raise ElfError(f"{self.path.name} is not little-endian")
        self.machine = struct.unpack_from("<H", self.data, 18)[0]
        self.e_entry, self.e_phoff, self.e_shoff = struct.unpack_from("<QQQ", self.data, 24)
        self.e_phentsize, self.e_phnum = struct.unpack_from("<HH", self.data, 54)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from("<HHH", self.data, 58)
        if self.machine != 0xB7:
            raise ElfError(f"{self.path.name} is not AArch64 (e_machine=0x{self.machine:x})")
        self.segments = self._segments()
        self.sections = self._sections()
        self.symbols, self.symbol_list = self._symbols()

    def _segments(self) -> list[Segment]:
        out: list[Segment] = []
        for index in range(self.e_phnum):
            base = self.e_phoff + index * self.e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", self.data, base
            )
            out.append(Segment(p_type, p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
        return out

    def _sections(self) -> list[Section]:
        if self.e_shnum == 0 or self.e_shstrndx >= self.e_shnum:
            return []
        raw: list[tuple[int, Section]] = []
        for index in range(self.e_shnum):
            base = self.e_shoff + index * self.e_shentsize
            nameoff, sh_type, sh_flags, addr, offset, size, link, _info, _align, entsize = (
                struct.unpack_from("<IIQQQQIIQQ", self.data, base)
            )
            raw.append((nameoff, Section("", sh_type, addr, offset, size, link, entsize, sh_flags)))
        strtab = raw[self.e_shstrndx][1]
        out: list[Section] = []
        for nameoff, section in raw:
            out.append(
                Section(self._string_at_offset(strtab, nameoff), section.type, section.addr,
                        section.offset, section.size, section.link, section.entsize, section.flags)
            )
        return out

    def _string_at_offset(self, strtab: Section, offset: int) -> str:
        start = strtab.offset + offset
        end = self.data.find(b"\0", start)
        if end < 0:
            return ""
        return self.data[start:end].decode("utf-8", "replace")

    def _symbols(self) -> tuple[dict[str, list[Symbol]], list[Symbol]]:
        by_name: dict[str, list[Symbol]] = {}
        every: list[Symbol] = []
        for section in self.sections:
            if section.type not in (SHT_SYMTAB, SHT_DYNSYM) or section.entsize < 24:
                continue
            if section.link >= len(self.sections):
                continue
            strtab = self.sections[section.link]
            count = section.size // section.entsize
            for index in range(count):
                base = section.offset + index * 24
                nameoff, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, base)
                name = self._string_at_offset(strtab, nameoff)
                if not name:
                    continue
                symbol = Symbol(
                    name=name,
                    value=value,
                    size=size,
                    bind=STB.get(info >> 4, f"BIND{info >> 4}"),
                    type=STT.get(info & 0xF, f"TYPE{info & 0xF}"),
                    shndx=shndx,
                )
                by_name.setdefault(name, []).append(symbol)
                every.append(symbol)
        return by_name, every

    def symbol(self, name: str) -> Symbol | None:
        """The defined symbol with this exact name; None when the image does not carry one."""
        for candidate in self.symbols.get(name, ()):
            if candidate.defined:
                return candidate
        return None

    def symbol_at(self, va: int) -> str | None:
        """The symbol an address falls in, as `name` or `name+0xN` for an offset inside it.

        Used to turn a pointer read out of the image back into the function or object it names,
        which is how a `file_operations` in rodata is recognised as a driver's handler table.
        """
        if not hasattr(self, "_by_value"):
            index: dict[int, Symbol] = {}
            for symbol in self.symbol_list:
                if symbol.defined and symbol.value and symbol.type in ("FUNC", "OBJECT", "NOTYPE"):
                    current = index.get(symbol.value)
                    if current is None or (symbol.type != "NOTYPE" and current.type == "NOTYPE"):
                        index[symbol.value] = symbol
            self._by_value = index
            self._sorted_values = sorted(index)
        values = self._sorted_values
        if not values:
            return None
        low, high = 0, len(values) - 1
        best = None
        while low <= high:
            middle = (low + high) // 2
            if values[middle] <= va:
                best = values[middle]
                low = middle + 1
            else:
                high = middle - 1
        if best is None:
            return None
        symbol = self._by_value[best]
        delta = va - best
        if delta == 0:
            return symbol.name
        if symbol.size and delta < symbol.size:
            return f"{symbol.name}+0x{delta:x}"
        return None

    def names_starting_with(self, *prefixes: str) -> list[Symbol]:
        wanted = tuple(prefixes)
        return sorted(
            (symbol for symbol in self.symbol_list if symbol.name.startswith(wanted) and symbol.defined),
            key=lambda symbol: (symbol.name, symbol.value),
        )

    def read(self, va: int, size: int) -> bytes | None:
        """Bytes stored at a virtual address, or None when no PT_LOAD backs them."""
        for segment in self.segments:
            if segment.type != PT_LOAD:
                continue
            if segment.vaddr <= va and va + size <= segment.vaddr + segment.filesz:
                start = segment.offset + (va - segment.vaddr)
                return self.data[start:start + size]
        return None

    def pointer(self, va: int) -> int | None:
        raw = self.read(va, 8)
        return struct.unpack("<Q", raw)[0] if raw else None

    def u32(self, va: int) -> int | None:
        raw = self.read(va, 4)
        return struct.unpack("<I", raw)[0] if raw else None

    def cstring(self, va: int, limit: int = 128) -> str | None:
        """The NUL-terminated string a pointer refers to, or None if it is not readable text."""
        raw = self.read(va, limit)
        if raw is None:
            return None
        end = raw.find(b"\0")
        candidate = raw if end < 0 else raw[:end]
        if not candidate or any(byte < 0x20 or byte > 0x7E for byte in candidate):
            return None
        return candidate.decode("ascii")

    def section_at(self, va: int) -> Section | None:
        """The most specific allocated section that contains a virtual address."""
        best: Section | None = None
        for section in self.sections:
            if section.addr and section.size and section.addr <= va < section.addr + section.size:
                if best is None or len(section.name) > len(best.name):
                    best = section
        return best

    def segment_at(self, va: int) -> Segment | None:
        for segment in self.segments:
            if segment.type != PT_LOAD:
                continue
            if segment.vaddr <= va < segment.vaddr + max(segment.filesz, segment.memsz):
                return segment
        return None

    def section_by_name(self, name: str) -> Section | None:
        return next((section for section in self.sections if section.name == name), None)

    def symbol_section(self, symbol: Symbol) -> Section | None:
        if 0 < symbol.shndx < len(self.sections):
            return self.sections[symbol.shndx]
        return None
