from reedsolo import RSCodec, ReedSolomonError
import lzma 
ECC_BYTES = 32  # 32byteのECC。最大で約16byte分の破損を訂正可能
rs = RSCodec(ECC_BYTES)

def add_ecc(data: bytes) -> bytes:
    """暗号化済みデータにECCを付与"""
    return bytes(rs.encode(data))

def recover_ecc(encoded: bytes) -> bytes:
    """ECC付きデータを復元"""
    try:
        decoded = rs.decode(encoded)
        return bytes(decoded[0])  # 元データ
    except ReedSolomonError as e:
        raise ValueError("ECCで復元できないほど破損しています") from e
    
def recover_data(data):
    try:
        compressed_data = recover_ecc(data)
    except ValueError as e:
        return None

    try:
        data = lzma.decompress(compressed_data)
    except lzma.LZMAError:
        print("エラーLZMA圧縮データの展開に失敗しました")
        return None
    return data