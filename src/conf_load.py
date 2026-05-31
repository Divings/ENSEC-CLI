import configparser
import os

from pathlib import Path
import os

APP_NAME = "ENSEC"

def config_path():
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

    return base / "config.ini"

CONFIG_FILE = str(config_path())

def load_config():
    """
    config.ini を読み込み、
    復号化後ファイル名に _decrypted を付けるかどうかを返す。
    
    戻り値:
        bool
    """

    # デフォルト設定
    default_config = {
        "add_decrypted_suffix": "true"
    }

    config = configparser.ConfigParser()

    # configファイルが存在しない場合は自動生成
    if not os.path.exists(CONFIG_FILE):
        config["Settings"] = default_config

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

        print(f"[INFO] {CONFIG_FILE} を作成しました")

    # 読み込み
    config.read(CONFIG_FILE, encoding="utf-8")

    # bool型として取得
    add_suffix = config.getboolean(
        "Settings",
        "add_decrypted_suffix",
        fallback=True
    )

    return add_suffix


# 使用例
if __name__ == "__main__":
    if load_config():
        print("復号化後ファイル名に _decrypted を付けます")
    else:
        print("復号化後ファイル名に _decrypted を付けません")