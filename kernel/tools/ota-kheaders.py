#!/usr/bin/env python3
"""Extract kheaders and .config from a Pico 4 Ultra OTA.

Both are embedded in the vendor kernel image (CONFIG_IKHEADERS, CONFIG_IKCONFIG).
payload.bin is STORED in the ZIP, so only the boot partition's span is fetched
(~16 MiB) instead of the whole ~6 GB archive.

Pins are checked because the OTA URL is mutable: a rotated build must fail
loudly rather than produce a module with wrong struct offsets.

Usage: ota-kheaders.py OTA --outdir DIR [--symbols FILE]
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import struct
import subprocess
import sys
import urllib.request

BOOT_MAGIC = b"ANDROID!"
PAYLOAD_MAGIC = b"CrAU"
XZ_MAGIC = b"\xfd7zXZ\x00"

# Pins for sparrow build UKQ1.240321.001/1786140970.
EXPECTED = {
    "boot": "f47a0486fcde8a38792dac35c9bedb789d91a5de752efd68ab308aead1448d8b",
    "kernel": "4f1fb1733cf0c49c0b8599ebf003ee0b20f45454b7f0fce0537e58f24e1a48d1",
    "kheaders": "06f662db7e2f2294c458a9791529f8d6d5790c5358bd101d5e28f2cf7740d932",
    # Hash of the gzip blob inside the kernel; the file written out is the
    # decompressed text (8c1f0a35...).
    "config": "e581591f6bb945b5115ed11381e2643e409ec02e47b217fb4b54f767b8afd97e",
}

CHUNK = 1 << 20


def log(msg: str) -> None:
    print(f"[ota] {msg}", file=sys.stderr)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Source:
    """Byte source backed by a local file or an HTTP range reader."""

    def __init__(self, spec: str):
        self.spec = spec
        self._http = spec.startswith("http://") or spec.startswith("https://")
        self._fh = None
        if not self._http:
            self._fh = open(spec, "rb")
            self.size = os.fstat(self._fh.fileno()).st_size
            return

        req = urllib.request.Request(spec, method="HEAD")
        with urllib.request.urlopen(req) as resp:
            self.size = int(resp.headers["Content-Length"])
        log(f"remote size {self.size} bytes")

    def read(self, offset: int, length: int) -> bytes:
        if not self._http:
            self._fh.seek(offset)
            return self._fh.read(length)

        end = min(offset + length, self.size) - 1
        req = urllib.request.Request(
            self.spec, headers={"Range": f"bytes={offset}-{end}"}
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status != 206:
                raise RuntimeError(
                    f"server ignored Range request (status {resp.status})"
                )
            return resp.read()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


def zip_local_header(src: Source, name: str) -> tuple[int, int]:
    """Return (data_offset, compressed_size) for one STORED member.

    Scans local file headers at the front of the archive, which is where the
    OTA writer emits payload.bin.
    """
    pos = 0
    limit = min(src.size, 1 << 20)
    while pos < limit:
        hdr = src.read(pos, 30)
        if len(hdr) < 30 or struct.unpack_from("<I", hdr)[0] != 0x04034B50:
            break
        (_, _, _, method, _, _, _, csize, _, nlen, elen) = struct.unpack(
            "<IHHHHHIIIHH", hdr
        )
        raw_name = src.read(pos + 30, nlen)
        member = raw_name.decode("utf-8", "replace")
        data_off = pos + 30 + nlen + elen
        if member == name:
            if method != 0:
                raise RuntimeError(f"{name} is compressed (method {method})")
            return data_off, csize
        pos = data_off + csize
    raise RuntimeError(f"{name} not found in archive")


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    val = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        val |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return val, pos
        shift += 7


def pb_fields(buf: bytes) -> dict[int, list]:
    out: dict[int, list] = {}
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = read_varint(buf, pos)
        elif wire == 2:
            size, pos = read_varint(buf, pos)
            val = buf[pos:pos + size]
            pos += size
        elif wire == 5:
            val = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        elif wire == 1:
            val = struct.unpack_from("<Q", buf, pos)[0]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
        out.setdefault(field, []).append(val)
    return out


def parse_manifest(manifest: bytes) -> tuple[dict[str, dict], int]:
    """Parse the payload manifest into {partition: {size, hash, ops}}."""
    root = pb_fields(manifest)
    block_size = (root.get(3) or [4096])[0]
    parts: dict[str, dict] = {}
    for raw in root.get(13, []):
        entry = pb_fields(raw)
        info = pb_fields((entry.get(7) or [b""])[0])
        ops = []
        for op_raw in entry.get(8, []):
            op = pb_fields(op_raw)
            ops.append(
                {
                    "type": (op.get(1) or [0])[0],
                    "data_offset": (op.get(2) or [0])[0],
                    "data_length": (op.get(3) or [0])[0],
                    "dst": [
                        ((pb_fields(e).get(1) or [0])[0],
                         (pb_fields(e).get(2) or [0])[0])
                        for e in op.get(6, [])
                    ],
                }
            )
        parts[(entry.get(1) or [b""])[0].decode()] = {
            "size": (info.get(1) or [0])[0],
            "hash": (info.get(2) or [b""])[0],
            "ops": ops,
        }
    return parts, block_size


def reconstruct(src: Source, data_start: int, part: dict, block: int) -> bytes:
    image = bytearray(part["size"])
    for op in part["ops"]:
        kind = op["type"]
        raw = src.read(data_start + op["data_offset"], op["data_length"])
        if len(raw) != op["data_length"]:
            raise RuntimeError("short read")
        if kind == 0:
            data = raw
        elif kind == 1:
            data = bz2.decompress(raw)
        elif kind == 8:
            data = lzma.decompress(raw)
        else:
            raise RuntimeError(f"unsupported op type {kind}")
        pos = 0
        for dst in op["dst"]:
            start_block, num_blocks = dst
            n = num_blocks * block
            image[start_block * block:start_block * block + n] = data[pos:pos + n]
            pos += n
    return bytes(image)


def parse_boot(img: bytes) -> tuple[bytes, bytes]:
    if img[:8] != BOOT_MAGIC:
        raise RuntimeError("not an Android boot image")
    kernel_size = struct.unpack_from("<I", img, 0x08)[0]
    ramdisk_size = struct.unpack_from("<I", img, 0x0C)[0]
    page_size = struct.unpack_from("<I", img, 0x24)[0] or 4096
    # v3+ puts the kernel in the page immediately after the header page.
    base = page_size
    kernel = img[base:base + kernel_size]
    rd_base = base + ((kernel_size + page_size - 1) // page_size) * page_size
    ramdisk = img[rd_base:rd_base + ramdisk_size]
    return kernel, ramdisk


def carve_xz_tar(kernel: bytes) -> bytes:
    """Find the kheaders stream without relying on a fixed offset."""
    pos = 0
    while True:
        pos = kernel.find(XZ_MAGIC, pos)
        if pos < 0:
            raise RuntimeError("no xz stream found in kernel")
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        try:
            out = dec.decompress(kernel[pos:])
        except lzma.LZMAError:
            pos += 1
            continue
        # A kernel kheaders blob decompresses to a tar archive.
        if dec.eof and len(out) > 1 << 20 and out[257:262] == b"ustar":
            return kernel[pos:len(kernel) - len(dec.unused_data)]
        pos += 1


def carve_config(kernel: bytes) -> bytes:
    start = kernel.find(b"IKCFG_ST")
    end = kernel.find(b"IKCFG_ED", start)
    if start < 0 or end < 0:
        raise RuntimeError("no embedded kernel config (CONFIG_IKCONFIG)")
    return kernel[start + 8:end]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract kheaders and .config from a Pico 4 Ultra OTA."
    )
    ap.add_argument("ota", help="OTA zip path or https:// URL")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--symbols", help="write kallsyms TSV here")
    ap.add_argument("--skip-pins", action="store_true",
                    help="accept any build (for investigating new OTAs)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    src = Source(args.ota)
    try:
        payload_off, payload_size = zip_local_header(src, "payload.bin")
        log(f"payload.bin data at {payload_off}, {payload_size} bytes")

        head = src.read(payload_off, 24)
        if head[:4] != PAYLOAD_MAGIC:
            raise RuntimeError("not an update_engine payload")
        _, manifest_size = struct.unpack(">QQ", head[4:20])
        sig_size = struct.unpack(">I", head[20:24])[0]

        manifest = src.read(payload_off + 24, manifest_size)
        parts, block_size = parse_manifest(manifest)
        if "boot" not in parts:
            raise RuntimeError("no boot partition")

        data_start = payload_off + 24 + manifest_size + sig_size
        boot = reconstruct(src, data_start, parts["boot"], block_size)
        if sha256(boot) != EXPECTED["boot"] and not args.skip_pins:
            raise RuntimeError("boot hash mismatch; OTA build changed")

        kernel, _ = parse_boot(boot)
        if sha256(kernel) != EXPECTED["kernel"] and not args.skip_pins:
            raise RuntimeError("kernel hash mismatch; OTA build changed")

        kheaders = carve_xz_tar(kernel)
        config_blob = carve_config(kernel)
        config = gzip.decompress(config_blob)

        artifacts = (("kheaders", kheaders), ("config", config_blob))
        for name, blob in artifacts:
            if not args.skip_pins and sha256(blob) != EXPECTED[name]:
                raise RuntimeError(f"{name} hash mismatch; OTA build changed")

        kh_path = os.path.join(args.outdir, "sparrow-kheaders.tar.xz")
        cfg_path = os.path.join(args.outdir, "sparrow.config")
        with open(kh_path, "wb") as fh:
            fh.write(kheaders)
        with open(cfg_path, "wb") as fh:
            fh.write(config)

        if args.symbols:
            helper = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "kallsyms.py")
            if not os.path.exists(helper):
                raise RuntimeError(f"kallsyms helper missing: {helper}")
            kernel_path = os.path.join(args.outdir, "boot-kernel")
            with open(kernel_path, "wb") as fh:
                fh.write(kernel)
            subprocess.run(
                [sys.executable, helper, kernel_path, "--json",
                 os.path.join(args.outdir, "kallsyms.json"),
                 "--symbols", args.symbols],
                check=True,
            )

        print(json.dumps({
            "kheaders": {"path": kh_path, "sha256": sha256(kheaders)},
            "config": {"path": cfg_path, "sha256": sha256(config)},
            "boot": sha256(boot),
            "kernel": sha256(kernel),
        }, indent=2))
        return 0
    finally:
        src.close()


if __name__ == "__main__":
    sys.exit(main())
