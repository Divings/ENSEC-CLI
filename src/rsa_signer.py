# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import base64
import os
import sys
import argparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from pathlib import Path


import os
from pathlib import Path

if os.name != "nt":
    import pwd

def _home_for_xdg():
    if os.name != "nt":
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and os.geteuid() == 0:
            return Path(pwd.getpwnam(sudo_user).pw_dir)

    return Path.home()

def KeyDir():
    import os

    APP_NAME = "ENSEC"
    HOME = _home_for_xdg()

    # XDG Base Directory Spec（無ければデフォルト）
    XDG_DATA_HOME   = Path(os.getenv("XDG_DATA_HOME",   HOME / ".local" / "share"))
    XDG_CACHE_HOME  = Path(os.getenv("XDG_CACHE_HOME",  HOME / ".cache"))
    base_dir = XDG_DATA_HOME / APP_NAME          # 永続データのベース
    key_dir = base_dir / "keys"                  # 鍵ディレクトリ
    key_dir.mkdir(parents=True, exist_ok=True)   # 念のため作る
    return key_dir

def generate_keys(private_key_path=None, public_key_path=None):
    try:
        key_dir = KeyDir()


        if private_key_path is None:
            private_key_path = os.path.join(key_dir, "private.pem")
        if public_key_path is None:
            public_key_path = os.path.join(key_dir, "public.pem")

        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            print(f"[INFO] Created key directory: {key_dir}")

        if not os.path.exists(private_key_path) and not os.path.exists(public_key_path):
            key = RSA.generate(2048)
            with open(private_key_path, "wb") as f:
                f.write(key.export_key())
            with open(public_key_path, "wb") as f:
                f.write(key.publickey().export_key())

            print(f"[SUCCESS] Key pair generated。Private key: {private_key_path} Public key: {public_key_path}")
    except Exception as e:
        print(f"[ERROR] 鍵生成中にエラーが発生しました: {e}")


# -------------- ここから追加（rsa_signer.py）--------------
import sqlite3
import getpass

APP_NAME = "ENSEC"

def SettingsDBPath() -> Path:
    HOME = _home_for_xdg()
    XDG_DATA_HOME = Path(os.getenv("XDG_DATA_HOME", HOME / ".local" / "share"))
    base_dir = XDG_DATA_HOME / APP_NAME
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "settings.db"

def is_private_key_protected() -> bool:
    db = SettingsDBPath()
    try:
        with sqlite3.connect(db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            cur = conn.execute("SELECT value FROM settings WHERE key=?", ("private_key_password_protect",))
            row = cur.fetchone()
        return (row[0] == "1") if row else False
    except Exception:
        return False
# -------------- ここまで追加 --------------


def get_signature_filename(file_path: str) -> str:
    return file_path + ".sig"

def sign_file(file_path: str, private_key_path: str = None):
    try:
        if private_key_path is None:
            base_dir = KeyDir()
            private_key_path = os.path.join(base_dir,"private.pem")

        signature_path = get_signature_filename(file_path)

        with open(private_key_path, "rb") as f:
            key_bytes = f.read()

        passphrase = None
        if is_private_key_protected():
            pw = getpass.getpass("Private key password: ")
            passphrase = pw if pw else None

        private_key = RSA.import_key(key_bytes, passphrase=passphrase)

        with open(file_path, "rb") as f:
            file_data = f.read()

        hash_obj = SHA256.new(file_data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)

        with open(signature_path, "wb") as f:
            f.write(base64.b64encode(signature))

        print(f"[SUCCESS] Signature saved: {signature_path}")
    except ValueError:
        print("[ERROR] Wrong password or invalid private key format.")
    except Exception as e:
        print(f"[ERROR] Error occurred during signature creation: {e}")

def verify_file_signature(file_path: str, public_key_path: str = None):
    try:
        if public_key_path is None:
            base_dir = KeyDir()
            public_key_path = os.path.join(base_dir, "public.pem")

        signature_path = get_signature_filename(file_path)

        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())

        with open(file_path, "rb") as f:
            file_data = f.read()
        with open(signature_path, "rb") as f:
            signature_b64 = f.read()

        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            print("[ERROR] Base64 decode failed: signature file is corrupted")
            return

        hash_obj = SHA256.new(file_data)
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print("[SUCCESS] Verification success: the signature matches the file")
    except (ValueError, TypeError):
        print("[FAIL] Verification failed: the signature is invalid or the file has been altered")
    except Exception as e:
        print(f"[ERROR] Error occurred during verification: {e}")

def main():
    parser = argparse.ArgumentParser(description="RSA署名ツール")
    parser.add_argument("mode", choices=["generate", "sign", "verify"], help="Operation mode")
    parser.add_argument("file", nargs="?", help="Target file")
    parser.add_argument("--priv", help="Private keyパス")
    parser.add_argument("--pub", help="Public keyパス")
    args = parser.parse_args()

    if args.mode == "generate":
        generate_keys(args.priv, args.pub)
    elif args.mode == "sign":
        if not args.file:
            print("🔴 Error: file path is required")
            return
        sign_file(args.file, args.priv)
    elif args.mode == "verify":
        if not args.file:
            print("🔴 Error: file path is required")
            return
        verify_file_signature(args.file, args.pub)

if __name__ == "__main__":
    main()
