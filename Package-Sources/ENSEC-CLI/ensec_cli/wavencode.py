# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import wave
import io
import struct
import lzma

def binary_to_wav_bytes(data: bytes, sample_rate=44100) -> bytes:
    # まずLZMA圧縮
    compressed_data = lzma.compress(data)

    buffer = io.BytesIO()

    # waveモジュールでバイナリ出力用のオブジェクトを開く
    with wave.open(buffer, 'wb') as wf:
        wf.setnchannels(1)         # モノラル
        wf.setsampwidth(2)         # 16bit（2バイト）
        wf.setframerate(sample_rate)

        # 各バイトを16bitのPCM波形に変換
        frames = []
        for byte in compressed_data:
            value = (byte - 128) * 256  # 中央値128基準
            frames.append(struct.pack('<h', value))  # Little endian

        wf.writeframes(b''.join(frames))

    return buffer.getvalue()  # WAV形式のバイト列を返す

def wav_bytes_to_binary(wav_data: bytes) -> bytes:
    buffer = io.BytesIO(wav_data)

    with wave.open(buffer, 'rb') as wf:
        raw_frames = wf.readframes(wf.getnframes())

    # 2バイトごとにPCMサンプルを読み取り、元のバイト列に戻す
    compressed = bytearray()
    for i in range(0, len(raw_frames), 2):
        sample = struct.unpack('<h', raw_frames[i:i+2])[0]
        byte = (sample // 256) + 128
        compressed.append(byte & 0xFF)

    # LZMA展開
    try:
        return lzma.decompress(compressed)
    except lzma.LZMAError:
        raise ValueError("LZMA展開に失敗しました。WAVファイルが壊れているか、不正な形式です。")
