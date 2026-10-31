#!/usr/bin/env python3
"""Build a symbol-only ELF64 "vmlinux" from a kallsyms dump.

check_symbol needs a `.symtab` to check undefined symbols against, but the
device ships no vendor vmlinux.  Input: `<type> <addr> <offset> <name>` TSV.

Usage: tools/mkvmlinux.py symbols.tsv -o vmlinux
"""

from __future__ import annotations

import argparse
import struct
import sys

EM_AARCH64 = 183

STB_GLOBAL = 1
STT_NOTYPE = 0


def parse_symbols(path: str) -> list[tuple[str, int]]:
    """Return [(name, address)] from a kallsyms dump."""
    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                addr_s, name = parts[1], parts[3]
            else:
                fields = line.split()
                if len(fields) < 3:
                    print(
                        f"mkvmlinux: {path}:{lineno}: cannot parse: {line!r}",
                        file=sys.stderr,
                    )
                    continue
                addr_s, name = fields[1], fields[-1]
            if not name or name in seen:
                continue
            try:
                addr = int(addr_s, 16)
            except ValueError:
                continue
            seen.add(name)
            out.append((name, addr))
    return out


def build_elf(symbols: list[tuple[str, int]]) -> bytes:
    """Emit an ELF64 relocatable object carrying the symbols in .symtab."""
    shstr = b"\0.symtab\0.strtab\0.shstrtab\0"
    off_symtab_name = shstr.index(b".symtab")
    off_strtab_name = shstr.index(b".strtab")
    off_shstrtab_name = shstr.index(b".shstrtab")

    strtab = bytearray(b"\0")
    name_offsets: list[int] = []
    for name, _addr in symbols:
        name_offsets.append(len(strtab))
        strtab += name.encode("utf-8", "replace") + b"\0"
    while len(strtab) % 8:
        strtab += b"\0"

    symtab = bytearray(b"\0" * 24)
    for (name, addr), name_off in zip(symbols, name_offsets):
        symtab += struct.pack(
            "<IBBHQQ",
            name_off,
            (STB_GLOBAL << 4) | STT_NOTYPE,
            0,
            0xFFF1,  # SHN_ABS
            addr,
            0,
        )

    ehsize = 64
    shoff = ehsize
    shnum = 4
    shentsize = 64
    data_start = shoff + shnum * shentsize

    symtab_off = data_start
    strtab_off = symtab_off + len(symtab)
    shstr_off = strtab_off + len(strtab)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3,  # ET_DYN
        EM_AARCH64,
        1,
        0,
        0,
        shoff,
        0,
        ehsize,
        0,
        0,
        shentsize,
        shnum,
        3,  # shstrndx
    )

    def shdr(name, stype, offset, size, link=0, ent=0):
        return struct.pack(
            "<IIQQQQIIQQ", name, stype, 0, 0, offset, size, link, 0, 8, ent
        )

    sections = [
        shdr(0, 0, 0, 0),  # SHT_NULL
        shdr(off_symtab_name, 2, symtab_off, len(symtab), link=2, ent=24),  # SYMTAB
        shdr(off_strtab_name, 3, strtab_off, len(strtab)),  # STRTAB
        shdr(off_shstrtab_name, 3, shstr_off, len(shstr)),  # .shstrtab
    ]

    blob = bytearray(ehdr)
    blob += b"".join(sections)
    blob += symtab
    blob += strtab
    blob += shstr
    return bytes(blob)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("symbols", help="kallsyms dump (type, addr, offset, name)")
    parser.add_argument("-o", "--output", required=True, help="output ELF path")
    args = parser.parse_args()

    symbols = parse_symbols(args.symbols)
    if not symbols:
        print(f"mkvmlinux: no symbols parsed from {args.symbols}", file=sys.stderr)
        return 1

    with open(args.output, "wb") as handle:
        handle.write(build_elf(symbols))

    print(f"mkvmlinux: wrote {len(symbols)} symbols to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
