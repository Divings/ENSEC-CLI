import os
import json
import struct
import configparser
import hashlib


# ======================================================
# SHA256
# ======================================================
def calc_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ======================================================
# 設定ファイルパス生成
# ======================================================
from pathlib import Path
import os

APP_NAME = "ENSEC"

def _default_db_path() -> Path:
    if os.name == "nt":
        home = Path.home()
        base = home / ".local" / "share" / APP_NAME
    else:
        xdg_data_home = Path(
            os.getenv(
                "XDG_DATA_HOME",
                Path.home() / ".local" / "share"
            )
        )
        base = xdg_data_home / APP_NAME

    base.mkdir(parents=True, exist_ok=True)

    return base / "split_config.ini"

def init_split_config():
    """
    split_config.ini が存在しない場合だけ、
    デフォルト（基本無効）の設定ファイルを生成する。
    既存ファイルがある場合は絶対に上書きしない。
    """
    config_path = _default_db_path()

    if os.path.exists(config_path):
        return

    config = configparser.ConfigParser()

    config["Split"] = {
        "enabled": "false",   # 基本無効
        "mode": "half",
        "parts": "2",
        "delmode": "false"
    }

    with open(config_path, "w", encoding="utf-8") as f:
        config.write(f)



def _load_split_settings() -> dict:

    settings = {
        "mode": "count",
        "parts": 4
    }

    if settings["parts"] < 1:
        settings["parts"] = 1

    return settings


# ======================================================
# chunk_size 自動判定
# ======================================================
def auto_chunk_size(file_size):
    MB = 1024 * 1024
    if file_size < 10 * MB:
        return None
    elif file_size < 100 * MB:
        return 5 * MB
    elif file_size < 500 * MB:
        return 10 * MB
    elif file_size < 1024 * MB:
        return 20 * MB
    else:
        return 50 * MB


HEADER_SIZE_LEN = 4


# ======================================================
# ヘッダー付きパート書き込み（署名付き）
# ======================================================
def _write_part(path, part_index, total_parts, original_name, data):
    header = {
        "original_name": original_name,
        "part_index": part_index,
        "total_parts": total_parts,
        "chunk_size": len(data),
        "sha256": calc_sha256(data)
    }

    header_raw = json.dumps(header).encode("utf-8")
    header_size = struct.pack(">I", len(header_raw))

    with open(path, "wb") as f:
        f.write(header_size)
        f.write(header_raw)
        f.write(data)


# ======================================================
# 分割（完全自動制御）
# ======================================================
def split_file_with_header(file_path):
    sett = _load_split_settings()

    #if not enable:
    #    return None

    mode = sett["mode"]
    parts = sett["parts"]

    total_size = os.path.getsize(file_path)
    original_name = os.path.basename(file_path)

    if mode == "half":
        total_parts = 2
        half = total_size // 2
        chunk_sizes = [half, total_size - half]

    else:
        total_parts = parts
        base = total_size // parts
        remainder = total_size % parts
        chunk_sizes = [base] * parts
        chunk_sizes[-1] += remainder

    out_paths = []

    with open(file_path, "rb") as fin:
        for i in range(total_parts):
            data = fin.read(chunk_sizes[i])
            part_path = f"{file_path}{i}"

            _write_part(
                path=part_path,
                part_index=i,
                total_parts=total_parts,
                original_name=original_name,
                data=data
            )

            out_paths.append(part_path)

    return out_paths


def is_delmode_enabled() -> bool:
    config_path = _default_db_path()

    if not os.path.exists(config_path):
        return False

    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")

    return config.getboolean("Split", "delmode", fallback=False)


# ======================================================
# 拡張子取得
# ======================================================
def get_file_extension(file_path: str) -> str:
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("ファイルパスは非空の文字列で指定してください。")
    _, ext = os.path.splitext(file_path)
    return ext


# ======================================================
# 結合（part0 → 自動判定）
# ======================================================
import re
def merge_from_part0(part0_path, output_path=None):
    part0_path = os.path.abspath(part0_path)

    folder = os.path.dirname(part0_path)
    base = os.path.basename(part0_path)
    prefix = base[:-1]

    pattern = re.compile(rf"^{re.escape(prefix)}\d+$")

    parts = [
        os.path.join(folder, fn)
        for fn in os.listdir(folder)
        if pattern.match(fn)
    ]

    return merge_files_with_header(parts, output_path)


# ======================================================
# 完全検証付き結合処理（署名付き）
# ======================================================
def merge_files_with_header(parts, output_path=None):
    part_info = []

    for path in parts:
        try:
            with open(path, "rb") as f:
                raw = f.read(4)
                if len(raw) < 4:
                    continue

                header_size = struct.unpack(">I", raw)[0]
                header_raw = f.read(header_size)
                header = json.loads(header_raw.decode("utf-8"))

                required = ("original_name", "part_index", "total_parts", "sha256")
                if not all(k in header for k in required):
                    raise ValueError(f"{path} のヘッダーが不完全です")

                part_info.append((header["part_index"], path, header))

        except Exception as e:
            raise ValueError(f"{path} の読み取り失敗: {e}")

    if not part_info:
        raise ValueError("適切なパートが見つかりません")

    part_info.sort(key=lambda x: x[0])

    names = {h["original_name"] for _,_,h in part_info}
    if len(names) != 1:
        raise ValueError("original_name が一致しません → 別ファイルのパートが混入")

    original_name = part_info[0][2]["original_name"]

    if ".." in original_name or "/" in original_name or "\\" in original_name:
        raise ValueError("original_name に危険な文字列があります")

    total_parts = part_info[0][2]["total_parts"]
    if total_parts != len(part_info):
        raise ValueError("total_parts と実パート数が一致しません")

    indexes = [idx for idx,_,_ in part_info]
    if sorted(indexes) != list(range(total_parts)):
        raise ValueError("part_index が不正です（重複・欠落・範囲外）")

    if output_path is None:
        folder = os.path.dirname(parts[0])
        output_path = os.path.join(folder, original_name)

    with open(output_path, "wb") as out:
        for idx, part_path, header in part_info:
            with open(part_path, "rb") as f:
                hsz = struct.unpack(">I", f.read(4))[0]
                f.read(hsz)
                payload = f.read()

                # --- 署名検証 ---
                if calc_sha256(payload) != header["sha256"]:
                    raise ValueError(f"{part_path} は改ざんされています（ハッシュ不一致）")

                out.write(payload)

    return output_path
