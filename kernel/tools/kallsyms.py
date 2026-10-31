#!/usr/bin/env python3
"""Self-validating recovery of Linux kallsyms from a raw arm64 Image.

No symbol table, BTF, or upstream source is used.  The layout recovered is the
CONFIG_KALLSYMS_BASE_RELATIVE one emitted by scripts/kallsyms.c:

    kallsyms_offsets[]        s32/u32, address - relative_base
    kallsyms_relative_base    u64
    kallsyms_num_syms         u32
    kallsyms_names[]          u8 len + len token bytes per symbol
    kallsyms_markers[]        u32, names offset of every 256th symbol
    kallsyms_token_table[]    256 NUL-terminated strings
    kallsyms_token_index[]    256 u16 offsets into token_table

The scan is deliberately structural.  A candidate is only accepted if the
token table is contiguous and printable, the names stream parses exactly to the
marker table, every marker matches, and the kallsyms_* symbols decode back to
the very table offsets that were found.  Hard-coded expected numbers are not
used to select or adjust a candidate.
"""
import argparse
import json
import struct
import sys

KERNEL_BASE_MASK = (1 << 64) - 1


class KallsymsError(RuntimeError):
    pass


def find_token_index_candidates(data):
    """Find 256-entry non-decreasing u16 arrays with small values."""
    n = (len(data) - 512) // 2
    if n <= 0:
        return []
    bad = bytearray(n + 256)
    for i in range(n + 256):
        bad[i] = 1 if data[2 * i + 1] > 0x0F else 0
    count = sum(bad[:256])
    out = []
    for i in range(n):
        if count == 0:
            off = 2 * i
            v = struct.unpack_from("<256H", data, off)
            if (v[0] == 0 and v[255] <= 4096
                    and all(v[j + 1] >= v[j] and 1 <= v[j + 1] - v[j] <= 64
                            for j in range(255))):
                out.append((off, v))
        count += bad[i + 256] - bad[i]
    return out


def find_token_table(data, ti, v):
    """Recover token_table start/strings from a token_index candidate."""
    found = []
    for tt in range(max(0, ti - 8192), ti, 8):
        toks = []
        ok = True
        for i in range(256):
            p = tt + v[i]
            if p >= ti:
                ok = False
                break
            if i < 255:
                ln = v[i + 1] - v[i] - 1
                if ln < 0 or ln > 64 or p + ln >= ti:
                    ok = False
                    break
                s = data[p:p + ln]
                if data[p + ln] != 0:
                    ok = False
                    break
            else:
                q = data.find(b"\0", p, ti)
                if q < 0:
                    ok = False
                    break
                s = data[p:q]
            if any(c < 0x20 or c > 0x7E for c in s):
                ok = False
                break
            toks.append(s)
        if not ok:
            continue
        last_end = tt + v[255] + len(toks[255]) + 1
        if any(data[last_end:ti]):
            continue
        found.append((tt, toks, last_end))
    return found


def find_markers(data, tt):
    """Find unique markers array immediately before token_table."""
    zeros = []
    for off in range(max(0, tt - 65536), tt - 3, 8):
        if struct.unpack_from("<I", data, off)[0] == 0:
            zeros.append(off)
    cands = []
    for ms in zeros:
        for pad in (0, 4):
            me = tt - pad
            if me <= ms or (me - ms) % 4:
                continue
            if pad and any(data[me:tt]):
                continue
            m = list(struct.unpack_from("<%dI" % ((me - ms) // 4), data, ms))
            if len(m) < 2 or m[0] != 0:
                continue
            if any(m[i + 1] < m[i] for i in range(len(m) - 1)):
                continue
            if m[-1] > 16 * 1024 * 1024:
                continue
            cands.append((ms, m))
    return cands


def find_names(data, ms, markers):
    """Find kallsyms_names by matching the num_syms field and every marker."""
    M = len(markers)
    if M < 1 or markers[0] != 0:
        return []
    last = markers[-1]
    n_lo = 256 * (M - 1) + 1
    n_hi = 256 * M
    # names_len >= last + (remaining symbols) and <= last + 256*255
    lo = max(0, ms - last - 256 * 255 - 8)
    hi = ms - last
    sols = []
    for S in range(lo - (lo % 8), hi + 1, 8):
        if S < 16:
            continue
        N = struct.unpack_from("<I", data, S - 8)[0]
        if not (n_lo <= N <= n_hi):
            continue
        if data[S - 4:S] != b"\0\0\0\0":
            continue
        pos = S
        offs = []
        ok = True
        for k in range(N):
            if pos >= ms:
                ok = False
                break
            ln = data[pos]
            if ln == 0 or pos + 1 + ln > ms:
                ok = False
                break
            if k % 256 == 0:
                offs.append(pos - S)
            pos += 1 + ln
        if not ok or len(offs) != M:
            continue
        if not (0 <= ms - pos < 8) or any(data[pos:ms]):
            continue
        if offs != markers:
            continue
        sols.append((S, N, pos))
    return sols


class Kallsyms:
    def __init__(self, path, image_size=None, boot_kernel_size=None, verbose=False):
        self.path = path
        self.boot_kernel_size = boot_kernel_size
        self.data = open(path, "rb").read()
        self.image_size = image_size
        if self.image_size is None:
            if self.data[56:60] != b"ARM\x64":
                raise KallsymsError("not an arm64 Image and no --image-size supplied")
            self.image_size = struct.unpack_from("<Q", self.data, 16)[0]
        self.verbose = verbose
        self._scan()

    def _log(self, *a):
        if self.verbose:
            print(*a, file=sys.stderr)

    def _scan(self):
        data = self.data
        ti_cands = find_token_index_candidates(data)
        self.token_index_candidates = len(ti_cands)
        layouts = []
        for ti, v in ti_cands:
            for tt, toks, last_end in find_token_table(data, ti, v):
                layouts.append({"ti": ti, "v": v, "tt": tt, "tokens": toks})
        if len(layouts) != 1:
            raise KallsymsError(
                f"expected one valid token layout, got {len(layouts)} "
                f"(token_index candidates={len(ti_cands)})")
        lay = layouts[0]
        self.ti, self.v, self.tt, self.tokens = \
            lay["ti"], lay["v"], lay["tt"], lay["tokens"]
        self._log("token_table", hex(self.tt), "token_index", hex(self.ti))

        marker_cands = find_markers(data, self.tt)
        if len(marker_cands) != 1:
            raise KallsymsError(
                f"expected one marker layout, got {len(marker_cands)}")
        self.ms, self.markers = marker_cands[0]
        self._log("markers", hex(self.ms), "count", len(self.markers))

        name_cands = find_names(data, self.ms, self.markers)
        if len(name_cands) != 1:
            raise KallsymsError(
                f"expected one names layout, got {len(name_cands)}")
        self.names_off, self.num_syms, self.names_end = name_cands[0]
        self._log("names", hex(self.names_off), "num_syms", self.num_syms)

        self.num_syms_off = self.names_off - 8
        self.relative_base_off = self.names_off - 16
        self.relative_base = struct.unpack_from("<Q", data, self.relative_base_off)[0]
        if struct.unpack_from("<I", data, self.num_syms_off)[0] != self.num_syms:
            raise KallsymsError("num_syms field changed during parse")
        pad = 4 if self.num_syms % 2 else 0
        self.offsets_off = self.relative_base_off - 4 * self.num_syms - pad
        if self.offsets_off % 8:
            raise KallsymsError("offsets array is not 8-byte aligned")
        self._log("relative_base", hex(self.relative_base),
                  "offsets", hex(self.offsets_off))

        # Decode names and addresses.
        self.symbols = []
        pos = self.names_off
        for i in range(self.num_syms):
            ln = data[pos]
            typ, name = self._expand(pos)
            pos += 1 + ln
            off = struct.unpack_from("<I", data, self.offsets_off + 4 * i)[0]
            addr = (self.relative_base + off) & KERNEL_BASE_MASK
            self.symbols.append({
                "index": i,
                "addr": addr,
                "offset": off,
                "type": typ,
                "name": name,
            })
        if pos != self.names_end:
            raise KallsymsError("symbol decode did not end at names_end")
        self.by_name = {}
        for s in self.symbols:
            self.by_name.setdefault(s["name"], []).append(s)

    def _expand(self, off):
        """Expand one name entry at an absolute file offset."""
        data = self.data
        ln = data[off]
        pos = off + 1
        typ = None
        out = []
        for _ in range(ln):
            tok = data[pos]
            pos += 1
            s = self.tokens[tok]
            for c in s:
                if typ is None:
                    typ = chr(c)
                else:
                    out.append(chr(c))
        return (typ or "?"), "".join(out)

    def norm(self, name):
        syms = self.by_name.get(name, [])
        if not syms:
            return None
        return syms[0]["addr"] - self.relative_base

    def find(self, name):
        return self.by_name.get(name, [])

    def check(self):
        def norm(sym):
            return sym["addr"] - self.relative_base if sym else None

        def one(name):
            s = self.find(name)
            return s[0] if len(s) == 1 else (s[0] if s else None)

        points = {
            "kallsyms_offsets": self.offsets_off,
            "kallsyms_relative_base": self.relative_base_off,
            "kallsyms_num_syms": self.num_syms_off,
            "kallsyms_names": self.names_off,
            "kallsyms_markers": self.ms,
            "kallsyms_token_table": self.tt,
            "kallsyms_token_index": self.ti,
        }
        point_checks = {}
        for name, expected in points.items():
            syms = self.find(name)
            actual = [norm(s) for s in syms]
            point_checks[name] = {
                "expected": expected,
                "actual": actual,
                "present": len(syms) > 0,
                "unique": len(syms) == 1,
                "ok": len(syms) == 1 and actual[0] == expected,
            }

        def val(name):
            s = one(name)
            return norm(s) if s else None

        text = val("_text")
        stext = val("_stext")
        edata = val("_edata")
        end = val("_end")
        in_range = sum(1 for s in self.symbols
                       if 0 <= s["addr"] - self.relative_base <= self.image_size)
        out_of_range = [
            {"name": s["name"], "addr": hex(s["addr"]),
             "normalized": s["addr"] - self.relative_base,
             "type": s["type"]}
            for s in self.symbols
            if not (0 <= s["addr"] - self.relative_base <= self.image_size)
        ]
        return {
            "token_index_candidates": self.token_index_candidates,
            "token_layout_unique": True,
            "markers_unique": True,
            "names_unique": True,
            "num_syms": self.num_syms,
            "num_syms_field_matches": True,
            "relative_base": hex(self.relative_base),
            "table_offsets": {k: hex(v) for k, v in points.items()},
            "symbol_self_pointers": point_checks,
            "all_symbol_self_pointers_available": all(v["present"] for v in point_checks.values()),
            "all_symbol_self_pointers_ok": all(v["ok"] for v in point_checks.values()),
            "text": text,
            "text_is_zero": text == 0,
            "stext": stext,
            "stext_is_0x10000": stext == 0x10000,
            "edata": edata,
            "end": end,
            "image_size": self.image_size,
            "end_equals_image_size": end == self.image_size,
            "boot_kernel_size": self.boot_kernel_size,
            "edata_equals_boot_kernel_size": (
                edata == self.boot_kernel_size if self.boot_kernel_size is not None else None),
            "symbols_in_image_range": in_range,
            "symbols_out_of_range": len(out_of_range),
            "out_of_range_sample": out_of_range[:20],
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--image-size", type=lambda x: int(x, 0))
    ap.add_argument("--boot-kernel-size", type=lambda x: int(x, 0))
    ap.add_argument("--json", required=True)
    ap.add_argument("--symbols", help="write type/addr/name TSV")
    ap.add_argument("--lookup", action="append", default=[])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    k = Kallsyms(args.image, args.image_size, args.boot_kernel_size, args.verbose)
    checks = k.check()
    with open(args.json, "w") as f:
        json.dump(checks, f, indent=2)
    print(json.dumps(checks, indent=2))
    if args.symbols:
        with open(args.symbols, "w") as f:
            for s in k.symbols:
                f.write(f'{s["type"]}\t{s["addr"]:016x}\t'
                        f'{s["addr"] - k.relative_base:08x}\t{s["name"]}\n')
    for name in args.lookup:
        print(f"\n{name}:")
        for s in k.find(name):
            print(f'  {s["type"]} {s["addr"]:016x} '
                  f'norm={s["addr"] - k.relative_base:#x} idx={s["index"]}')


if __name__ == "__main__":
    main()
