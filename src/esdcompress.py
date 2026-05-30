#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esdcompress.py
EncryptSecureDEC向けの「1ファイル完結」専用圧縮ライブラリ。
- ブロック分割（デフォルト 64KiB）
- LZSS圧縮（窓4096, 長さ3〜18）
- ヘッダSHA-256でヘッダ破損検出
- 各ブロックCRC32で改ざん/破損検出
- ストリームAPI（ファイル/メモリ/パイプで使える）
- CLI付き

使い方:
  圧縮:   python esdcompress.py compress input.bin output.esdc
  展開:   python esdcompress.py decompress input.esdc output.bin
  情報:   python esdcompress.py info input.esdc

破損してても可能な限り吐き出す:
  python esdcompress.py decompress --partial broken.esdc recovered.bin
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import struct
import sys
import time
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Optional, Tuple


# =========================
# Constants / Format
# =========================

MAGIC = b"ESDC"
VERSION = 1

FLAG_COMPRESSED = 0x01  # 圧縮モード（LZSS）で保存されたブロック
# 予約: 将来拡張用にフラグは増やせる

DEFAULT_BLOCK_SIZE = 65536  # 64KiB

# LZSS parameters
LZ_WINDOW_SIZE = 4096
LZ_MIN_MATCH = 3
LZ_MAX_MATCH = 18


# =========================
# Exceptions
# =========================

class ESDCError(Exception):
    pass

class ESDCFormatError(ESDCError):
    pass

class ESDCCorruptError(ESDCError):
    def __init__(self, message: str, recovered_bytes: int = 0, recovered_blocks: int = 0):
        super().__init__(message)
        self.recovered_bytes = recovered_bytes
        self.recovered_blocks = recovered_blocks


# =========================
# Header
# =========================

@dataclass(frozen=True)
class Header:
    version: int
    flags: int
    block_size: int

    def pack_without_hash(self) -> bytes:
        # MAGIC(4) + VERSION(1) + FLAGS(1) + BLOCK_SIZE(4)
        return MAGIC + bytes([self.version, self.flags]) + struct.pack(">I", self.block_size)

    def hash(self) -> bytes:
        return hashlib.sha256(self.pack_without_hash()).digest()

def write_header(fout: BinaryIO, block_size: int, compressed: bool) -> Header:
    if not (1024 <= block_size <= 16 * 1024 * 1024):
        raise ValueError("block_size must be between 1024 and 16777216 bytes")

    flags = 0
    if compressed:
        flags |= FLAG_COMPRESSED

    hdr = Header(version=VERSION, flags=flags, block_size=block_size)
    core = hdr.pack_without_hash()
    h = hdr.hash()
    fout.write(core)
    fout.write(h)
    return hdr

def read_exact(fin: BinaryIO, n: int) -> bytes:
    data = fin.read(n)
    if len(data) != n:
        raise EOFError(f"Unexpected EOF (wanted {n} bytes, got {len(data)})")
    return data

def read_header(fin: BinaryIO) -> Header:
    core = read_exact(fin, 4 + 1 + 1 + 4)
    magic = core[:4]
    if magic != MAGIC:
        raise ESDCFormatError("Invalid MAGIC (not an ESDC file)")

    version = core[4]
    flags = core[5]
    block_size = struct.unpack(">I", core[6:10])[0]
    stored_hash = read_exact(fin, 32)

    calc_hash = hashlib.sha256(core).digest()
    if stored_hash != calc_hash:
        raise ESDCCorruptError("Header corrupted (SHA-256 mismatch)", recovered_bytes=0, recovered_blocks=0)

    if version != VERSION:
        raise ESDCFormatError(f"Unsupported version: {version} (expected {VERSION})")

    if not (1024 <= block_size <= 16 * 1024 * 1024):
        raise ESDCFormatError(f"Invalid block_size in header: {block_size}")

    return Header(version=version, flags=flags, block_size=block_size)


# =========================
# LZSS (compress/decompress)
# =========================
#
# 符号化方式:
# - 8トークンごとに flags(1 byte)
#   - bit=1: literal(1 byte)
#   - bit=0: match(2 bytes)
# - match は 2 bytes:
#     12-bit offset (1..4096), 4-bit length_code (0..15) => length = length_code + 3
#
# offset は「現在位置から過去へ何バイト戻るか」
# 例: offset=1 は直前の1バイト
#

def _find_longest_match(data: bytes, pos: int) -> Tuple[int, int]:
    """
    pos地点で、過去4096以内から最長一致を探す。
    return: (best_offset, best_len)
    best_len < 3 なら (0,0)
    """
    end = len(data)
    max_len = min(LZ_MAX_MATCH, end - pos)
    if max_len < LZ_MIN_MATCH:
        return (0, 0)

    window_start = max(0, pos - LZ_WINDOW_SIZE)
    best_len = 0
    best_offset = 0

    # ざっくり高速化: 先頭3バイトが合う候補だけ当てる
    needle = data[pos:pos + LZ_MIN_MATCH]
    # 後ろから探すと近い参照になりやすい（圧縮に効きやすい場合が多い）
    for j in range(pos - 1, window_start - 1, -1):
        if data[j:j + LZ_MIN_MATCH] != needle:
            continue

        # 伸ばす
        k = LZ_MIN_MATCH
        while k < max_len and data[j + k] == data[pos + k]:
            k += 1

        if k > best_len:
            best_len = k
            best_offset = pos - j
            if best_len == max_len:
                break

    if best_len >= LZ_MIN_MATCH and 1 <= best_offset <= LZ_WINDOW_SIZE:
        return (best_offset, best_len)
    return (0, 0)

def lzss_compress(raw: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(raw)

    while i < n:
        flags_pos = len(out)
        out.append(0)  # flags placeholder
        flags = 0
        bit = 0

        while bit < 8 and i < n:
            offset, mlen = _find_longest_match(raw, i)

            if mlen >= LZ_MIN_MATCH:
                # match token: flag bit=0
                length_code = mlen - LZ_MIN_MATCH  # 0..15
                if length_code > 0x0F:
                    length_code = 0x0F
                    mlen = length_code + LZ_MIN_MATCH

                # pack offset (12-bit) and length_code (4-bit)
                # first byte: high 8 of offset? Actually: (offset-1) in 12-bit is common,
                # but here we store offset-1 to fit 0..4095.
                off = offset - 1
                b1 = (off >> 4) & 0xFF
                b2 = ((off & 0x0F) << 4) | (length_code & 0x0F)
                out.append(b1)
                out.append(b2)

                i += mlen
            else:
                # literal: flag bit=1
                flags |= (1 << bit)
                out.append(raw[i])
                i += 1

            bit += 1

        out[flags_pos] = flags

    return bytes(out)

def lzss_decompress(comp: bytes, expected_size: int) -> bytes:
    out = bytearray()
    p = 0
    clen = len(comp)

    while len(out) < expected_size and p < clen:
        flags = comp[p]
        p += 1

        for bit in range(8):
            if len(out) >= expected_size:
                break

            is_lit = (flags >> bit) & 1
            if is_lit:
                if p >= clen:
                    raise ESDCCorruptError("Unexpected EOF in LZSS literal stream")
                out.append(comp[p])
                p += 1
            else:
                if p + 1 >= clen:
                    raise ESDCCorruptError("Unexpected EOF in LZSS match stream")
                b1 = comp[p]
                b2 = comp[p + 1]
                p += 2

                off = ((b1 << 4) | (b2 >> 4)) + 1  # stored offset-1
                length_code = b2 & 0x0F
                mlen = length_code + LZ_MIN_MATCH

                if off < 1 or off > LZ_WINDOW_SIZE:
                    raise ESDCCorruptError(f"Invalid LZSS offset: {off}")

                # copy from out[-off]
                start = len(out) - off
                if start < 0:
                    raise ESDCCorruptError("LZSS back-reference before start")

                for _ in range(mlen):
                    if len(out) >= expected_size:
                        break
                    out.append(out[start])
                    start += 1

    if len(out) != expected_size:
        raise ESDCCorruptError(
            f"LZSS decompressed size mismatch (got {len(out)}, expected {expected_size})"
        )
    return bytes(out)


# =========================
# Block IO
# =========================

def _crc32_block(raw_len: int, data_len: int, data: bytes) -> int:
    # CRC over: RAW_LEN(4) + DATA_LEN(4) + DATA
    buf = struct.pack(">II", raw_len, data_len) + data
    return zlib.crc32(buf) & 0xFFFFFFFF

def write_block(fout: BinaryIO, raw_block: bytes, compressed: bool) -> None:
    raw_len = len(raw_block)

    if compressed and raw_len > 0:
        comp = lzss_compress(raw_block)
        data = comp
    else:
        data = raw_block

    data_len = len(data)
    crc = _crc32_block(raw_len, data_len, data)

    fout.write(struct.pack(">II", raw_len, data_len))
    if data_len:
        fout.write(data)
    fout.write(struct.pack(">I", crc))

def read_block(fin: BinaryIO) -> Optional[Tuple[int, int, bytes, int]]:
    """
    return None if clean EOF before any block header bytes.
    else returns (raw_len, data_len, data, crc)
    """
    head = fin.read(8)
    if head == b"":
        return None
    if len(head) != 8:
        raise ESDCCorruptError("Truncated block header")

    raw_len, data_len = struct.unpack(">II", head)

    if data_len > 256 * 1024 * 1024:
        raise ESDCCorruptError(f"Unreasonable data_len: {data_len}")

    data = read_exact(fin, data_len) if data_len else b""
    crc_bytes = read_exact(fin, 4)
    (crc,) = struct.unpack(">I", crc_bytes)
    return (raw_len, data_len, data, crc)


# =========================
# Stream API
# =========================

@dataclass
class DecompressResult:
    recovered_bytes: int
    recovered_blocks: int
    stopped_reason: Optional[str] = None  # None means OK

def compress_stream(
    fin: BinaryIO,
    fout: BinaryIO,
    block_size: int = DEFAULT_BLOCK_SIZE,
    compress: bool = True,
) -> None:
    write_header(fout, block_size=block_size, compressed=compress)

    while True:
        chunk = fin.read(block_size)
        if not chunk:
            break
        write_block(fout, chunk, compressed=compress)

def decompress_stream(
    fin: BinaryIO,
    fout: BinaryIO,
    allow_partial: bool = False,
) -> DecompressResult:
    hdr = read_header(fin)
    compressed = bool(hdr.flags & FLAG_COMPRESSED)

    recovered_bytes = 0
    recovered_blocks = 0

    while True:
        try:
            blk = read_block(fin)
            if blk is None:
                return DecompressResult(recovered_bytes, recovered_blocks, None)

            raw_len, data_len, data, stored_crc = blk
            calc_crc = _crc32_block(raw_len, data_len, data)
            if stored_crc != calc_crc:
                raise ESDCCorruptError(
                    f"CRC mismatch at block {recovered_blocks} (stored={stored_crc:08x}, calc={calc_crc:08x})",
                    recovered_bytes=recovered_bytes,
                    recovered_blocks=recovered_blocks
                )

            if raw_len == 0:
                # 空ブロックは許容（念のため）
                recovered_blocks += 1
                continue

            if compressed:
                raw = lzss_decompress(data, expected_size=raw_len)
            else:
                if data_len != raw_len:
                    raise ESDCCorruptError(
                        f"Non-compressed mode but data_len!=raw_len at block {recovered_blocks}",
                        recovered_bytes=recovered_bytes,
                        recovered_blocks=recovered_blocks
                    )
                raw = data

            fout.write(raw)
            recovered_bytes += len(raw)
            recovered_blocks += 1

        except (EOFError, ESDCError) as e:
            if allow_partial:
                return DecompressResult(
                    recovered_bytes=recovered_bytes,
                    recovered_blocks=recovered_blocks,
                    stopped_reason=str(e),
                )
            if isinstance(e, ESDCCorruptError):
                # 破損箇所の回収状況を含める
                raise ESDCCorruptError(str(e), recovered_bytes, recovered_blocks) from e
            raise


# =========================
# Convenience file API
# =========================

def compress_file(
    in_path: str,
    out_path: str,
    block_size: int = DEFAULT_BLOCK_SIZE,
    compress: bool = True,
) -> None:
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        compress_stream(fin, fout, block_size=block_size, compress=compress)

def decompress_file(
    in_path: str,
    out_path: str,
    allow_partial: bool = False,
) -> DecompressResult:
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        return decompress_stream(fin, fout, allow_partial=allow_partial)

def get_info(path: str) -> dict:
    with open(path, "rb") as f:
        hdr = read_header(f)
        # ブロック数は走査して数える（info用途）
        blocks = 0
        raw_total = 0
        data_total = 0
        while True:
            blk = read_block(f)
            if blk is None:
                break
            raw_len, data_len, data, crc = blk
            blocks += 1
            raw_total += raw_len
            data_total += data_len

        return {
            "version": hdr.version,
            "flags": hdr.flags,
            "compressed": bool(hdr.flags & FLAG_COMPRESSED),
            "block_size": hdr.block_size,
            "blocks": blocks,
            "raw_total": raw_total,
            "data_total": data_total,
        }


# =========================
# CLI
# =========================

def _cmd_compress(args: argparse.Namespace) -> int:
    compress_file(
        args.input,
        args.output,
        block_size=args.block_size,
        compress=(not args.no_compress),
    )
    return 0

def _cmd_decompress(args: argparse.Namespace) -> int:
    try:
        res = decompress_file(args.input, args.output, allow_partial=args.partial)
        if res.stopped_reason is None:
            return 0
        else:
            print(
                f"[partial] stopped: {res.stopped_reason}\n"
                f"[partial] recovered_blocks={res.recovered_blocks}, recovered_bytes={res.recovered_bytes}",
                file=sys.stderr
            )
            return 2
    except ESDCCorruptError as e:
        print(
            f"[error] {e}\n"
            f"[error] recovered_blocks={e.recovered_blocks}, recovered_bytes={e.recovered_bytes}",
            file=sys.stderr
        )
        return 1

def _cmd_info(args: argparse.Namespace) -> int:
    info = get_info(args.input)
    for k, v in info.items():
        print(f"{k}: {v}")
    return 0

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="esdcompress.py", description="ESDC: EncryptSecureDEC専用 圧縮フォーマット")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("compress", help="Compress input -> output.esdc")
    pc.add_argument("input")
    pc.add_argument("output")
    pc.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)
    pc.add_argument("--no-compress", action="store_true", help="Disable LZSS (store raw blocks)")
    pc.set_defaults(func=_cmd_compress)

    pd = sub.add_parser("decompress", help="Decompress input.esdc -> output")
    pd.add_argument("input")
    pd.add_argument("output")
    pd.add_argument("--partial", action="store_true", help="Recover as much as possible then stop on error")
    pd.set_defaults(func=_cmd_decompress)

    pi = sub.add_parser("info", help="Show container info (counts blocks by scanning)")
    pi.add_argument("input")
    pi.set_defaults(func=_cmd_info)

    return p

def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
