"""ENSEC legacy Reed-Solomon ECC helpers for .vdec files."""
from pathlib import Path
import lzma
from reedsolo import RSCodec, ReedSolomonError

ECC_BYTES = 32
rs = RSCodec(ECC_BYTES)


def add_ecc(data: bytes) -> bytes:
    return bytes(rs.encode(data))


def recover_ecc(encoded: bytes) -> bytes:
    try:
        return bytes(rs.decode(encoded)[0])
    except (ReedSolomonError, ValueError, IndexError) as exc:
        raise ValueError('ECCで復元できないほど破損しています') from exc


def recover_data(data: bytes):
    try:
        return lzma.decompress(recover_ecc(data))
    except (ValueError, lzma.LZMAError, EOFError):
        return None


def inspect_ecc(encoded: bytes) -> tuple[str, bytes]:
    """Return (healthy|repairable, corrected compressed LZMA bytes).

    A file without a trusted checksum/header cannot be authenticated by ECC alone.
    """
    compressed = recover_ecc(encoded)
    # Validate the recovered LZMA stream before reporting a successful recovery.
    try:
        lzma.decompress(compressed)
    except (lzma.LZMAError, EOFError) as exc:
        raise ValueError('ECC復元後のLZMAデータが不正です') from exc
    canonical = add_ecc(compressed)
    return ('healthy' if canonical == encoded else 'repairable', compressed)


def verify_ecc_file(path: str) -> str:
    status, _ = inspect_ecc(Path(path).read_bytes())
    return status


def repair_ecc_file(path: str, output_path: str | None = None) -> str:
    src = Path(path)
    status, compressed = inspect_ecc(src.read_bytes())
    if status == 'healthy':
        return 'healthy'
    target = Path(output_path) if output_path else src.with_name(src.stem + '_repaired' + src.suffix)
    if target.resolve() == src.resolve():
        raise ValueError('元ファイルへの上書きはできません')
    with target.open('xb') as f:
        f.write(add_ecc(compressed))
    return str(target)


def extract_ecc_payload(path: str, output_path: str | None = None) -> str:
    src = Path(path)
    _, compressed = inspect_ecc(src.read_bytes())
    target = Path(output_path) if output_path else src.with_name(src.name + '.lzma')
    if target.resolve() == src.resolve():
        raise ValueError('元ファイルへの上書きはできません')
    with target.open('xb') as f:
        f.write(compressed)
    return str(target)


# RSA .rdec ECC envelope v1. Legacy .rdec files have no envelope.
# Digest protects against undetected decoding errors, not malicious tampering.
import hashlib
import struct

RDEC_ECC_MAGIC = b"ENSEC-RDEC-ECC\x00\x01"
RDEC_ECC_HEADER_SIZE = len(RDEC_ECC_MAGIC) + 8 + 32


def is_rdec_ecc(blob: bytes) -> bool:
    return blob.startswith(RDEC_ECC_MAGIC)


def wrap_rdec_ecc(payload: bytes) -> bytes:
    return (RDEC_ECC_MAGIC + struct.pack(">Q", len(payload))
            + hashlib.sha256(payload).digest() + add_ecc(payload))


def inspect_rdec_ecc(blob: bytes) -> tuple[str, bytes]:
    if not is_rdec_ecc(blob):
        raise ValueError("ECC未対応の従来形式.rdecです")
    if len(blob) < RDEC_ECC_HEADER_SIZE:
        raise ValueError("ECCヘッダーが途中で切れています")
    original_size = struct.unpack(">Q", blob[len(RDEC_ECC_MAGIC):len(RDEC_ECC_MAGIC)+8])[0]
    digest = blob[len(RDEC_ECC_MAGIC)+8:RDEC_ECC_HEADER_SIZE]
    payload = recover_ecc(blob[RDEC_ECC_HEADER_SIZE:])
    if len(payload) != original_size or hashlib.sha256(payload).digest() != digest:
        raise ValueError("復元データの長さまたはSHA-256が一致しません")
    canonical = wrap_rdec_ecc(payload)
    return ("healthy" if canonical == blob else "repairable", payload)


def unwrap_rdec_ecc(blob: bytes) -> bytes:
    return inspect_rdec_ecc(blob)[1] if is_rdec_ecc(blob) else blob


def verify_rdec_ecc_file(path: str) -> str:
    return inspect_rdec_ecc(Path(path).read_bytes())[0]


def repair_rdec_ecc_file(path: str, output_path: str | None = None) -> str:
    src = Path(path)
    status, payload = inspect_rdec_ecc(src.read_bytes())
    if status == "healthy":
        return "healthy"
    target = Path(output_path) if output_path else src.with_name(src.stem + "_repaired" + src.suffix)
    if target.resolve() == src.resolve():
        raise ValueError("元ファイルへの上書きはできません")
    with target.open("xb") as f:
        f.write(wrap_rdec_ecc(payload))
    return str(target)


def extract_rdec_ecc_payload(path: str, output_path: str | None = None) -> str:
    src = Path(path)
    _, payload = inspect_rdec_ecc(src.read_bytes())
    target = Path(output_path) if output_path else src.with_name(src.name + ".raw")
    if target.resolve() == src.resolve():
        raise ValueError("元ファイルへの上書きはできません")
    with target.open("xb") as f:
        f.write(payload)
    return str(target)
