import os, sys, hashlib, sqlite3, traceback, getpass
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from Crypto.Cipher import AES

# ===============================================
# Constants
# ===============================================

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

HOME = _home_for_xdg()

APP_NAME = "ENSEC"

# XDG Base Directory Spec（無ければデフォルト）
XDG_CONFIG_HOME = Path(os.getenv("XDG_CONFIG_HOME", HOME / ".config"))
XDG_DATA_HOME   = Path(os.getenv("XDG_DATA_HOME",   HOME / ".local" / "share"))
XDG_CACHE_HOME  = Path(os.getenv("XDG_CACHE_HOME",  HOME / ".cache"))


# ディレクトリ設計（非sudoでも確実に書ける）
CONFIG_DIR = XDG_CONFIG_HOME / APP_NAME
DATA_DIR   = XDG_DATA_HOME / APP_NAME
CACHE_DIR  = XDG_CACHE_HOME / APP_NAME

KEY_DIR = DATA_DIR / "keys"
TRUSTED_DIR = DATA_DIR / "TrustedKeys"

RSA_KEY_PATH = KEY_DIR / "private.pem"
RSA_PUB_PATH = KEY_DIR / "public.pem"

DB_PATH = DATA_DIR / "settings.db"

BLOCKCHAIN_HEADER = b"BLOCKCHAIN_DATA_START\n"


# 2026/2/16
def init_settings_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()

def get_setting(key: str, default: str = None) -> str:
    init_settings_db()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
    return row[0] if row else default

def set_setting(key: str, value: str) -> None:
    init_settings_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value)
        )
        conn.commit()

def is_private_key_protected() -> bool:
    # "1" ならON、"0" ならOFF
    return get_setting("private_key_password_protect", "0") == "1"

def set_private_key_protected(enabled: bool) -> None:
    set_setting("private_key_password_protect", "1" if enabled else "0")

# -------------- ここから追加（rsa_encryptor.py）--------------

import datetime

def is_pem_encrypted(pem_bytes: bytes) -> bool:
    lines = pem_bytes.splitlines()

    # PKCS#8 encrypted
    if any(b"BEGIN ENCRYPTED PRIVATE KEY" in line for line in lines[:5]):
        return True

    # TraditionalOpenSSL encrypted (Proc-Type / DEK-Info が入る)
    # 例:
    # -----BEGIN RSA PRIVATE KEY-----
    # Proc-Type: 4,ENCRYPTED
    # DEK-Info: AES-256-CBC,....
    if any(b"ENCRYPTED" in line for line in lines[:15]):
        return True
    if any(b"DEK-Info:" in line for line in lines[:15]):
        return True

    return False


def backup_file(path: Path) -> Path:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bak = path.with_suffix(path.suffix + f".bak_{ts}")
    bak.write_bytes(path.read_bytes())
    os.chmod(bak, 0o600)
    return bak

from typing import Optional

def reserialize_private_key_to_path(private_key, out_path: Path, password: Optional[str]):
    if password is None:
        enc_algo = serialization.NoEncryption()
    else:
        enc_algo = serialization.BestAvailableEncryption(password.encode("utf-8"))

    out_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc_algo,
        )
    )
    os.chmod(out_path, 0o600)

def migrate_private_key_encrypt_inplace():
    """
    既存 private.pem を読み取り、パスワード暗号化して上書きする（移行）
    """
    if not RSA_KEY_PATH.exists():
        print(f"[ERROR] private key not found: {RSA_KEY_PATH}")
        return 1

    pem = RSA_KEY_PATH.read_bytes()
    if is_pem_encrypted(pem):
        print("[INFO] private.pem is already encrypted. (No changes)")
        return 0

    # 平文鍵として読み込み（ここで失敗するならファイル破損など）
    try:
        priv = serialization.load_pem_private_key(pem, password=None)
    except Exception as e:
        print(f"[ERROR] Failed to load existing private key: {e}")
        return 1

    pw1 = getpass.getpass("New private key password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if not pw1 or pw1 != pw2:
        print("[ERROR] Password mismatch or empty. Aborting.")
        return 1

    bak = backup_file(RSA_KEY_PATH)
    try:
        reserialize_private_key_to_path(priv, RSA_KEY_PATH, pw1)
        set_private_key_protected(True)  # 既に前のターンで追加した想定
        print(f"[SUCCESS] Migrated: plaintext -> encrypted (backup: {bak})")
        return 0
    except Exception as e:
        # 失敗したらバックアップで戻す
        RSA_KEY_PATH.write_bytes(bak.read_bytes())
        os.chmod(RSA_KEY_PATH, 0o600)
        print(f"[ERROR] Migration failed; restored from backup. reason={e}")
        return 1

def migrate_private_key_decrypt_inplace():
    """
    既存 private.pem を読み取り、パスワード解除して平文PEMとして上書きする（解除）
    """
    if not RSA_KEY_PATH.exists():
        print(f"[ERROR] private key not found: {RSA_KEY_PATH}")
        return 1

    pem = RSA_KEY_PATH.read_bytes()
    if not is_pem_encrypted(pem):
        print("[INFO] private.pem is already plaintext. (No changes)")
        return 0

    pw = getpass.getpass("Current private key password: ")
    if not pw:
        print("[ERROR] Empty password. Aborting.")
        return 1

    # 暗号化鍵として読み込み
    try:
        priv = serialization.load_pem_private_key(pem, password=pw.encode("utf-8"))
    except Exception:
        print("[ERROR] Wrong password or invalid encrypted key.")
        return 1

    # 念押し（うっかり解除を防ぐ）
    confirm = input("Type 'YES' to decrypt and overwrite private.pem as plaintext: ").strip()
    if confirm != "YES":
        print("[INFO] Cancelled.")
        return 0

    bak = backup_file(RSA_KEY_PATH)
    try:
        reserialize_private_key_to_path(priv, RSA_KEY_PATH, password=None)
        set_private_key_protected(False)
        print(f"[SUCCESS] Migrated: encrypted -> plaintext (backup: {bak})")
        return 0
    except Exception as e:
        RSA_KEY_PATH.write_bytes(bak.read_bytes())
        os.chmod(RSA_KEY_PATH, 0o600)
        print(f"[ERROR] Decrypt migration failed; restored from backup. reason={e}")
        return 1

# -------------- ここまで追加 --------------


def ensure_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_DIR.mkdir(parents=True, exist_ok=True)

ensure_dirs()
# from cryptography.hazmat.backends import default_backend
# ===============================================
# RSA Key Generation
# ===============================================
def ensure_rsa_keys():
    """
    Ensure RSA key pair exists.
    If not found, generate new RSA 2048bit key pair.
    """
    if not KEY_DIR.exists():
        KEY_DIR.mkdir(parents=True)
        print(f"[INFO] Created key directory: {KEY_DIR}")

    if not RSA_KEY_PATH.exists() or not RSA_PUB_PATH.exists():
        print("[INFO] Generating new RSA key pair...")
        try:
            private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
            )
        except TypeError:
            from cryptography.hazmat.backends import default_backend

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            backend=default_backend()
            )
        
        public_key = private_key.public_key()

        # ★ここが追加ポイント：設定で暗号化ONならパスワード付きで保存
        if is_private_key_protected():
            pw1 = getpass.getpass("Private key password: ")
            pw2 = getpass.getpass("Confirm password: ")
            if pw1 != pw2 or not pw1:
                print("[ERROR] Password mismatch or empty. Aborting key generation.")
                return
            enc_algo = serialization.BestAvailableEncryption(pw1.encode("utf-8"))
        else:
            enc_algo = serialization.NoEncryption()

        # Save private key
        with open(RSA_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=enc_algo
                )
            )
        os.chmod(RSA_KEY_PATH, 0o600)

        # Save public key
        with open(RSA_PUB_PATH, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print(f"[INFO] RSA key pair generated in {KEY_DIR}")
    else:
        print(f"[INFO] RSA keys already exist in {KEY_DIR}")

# ===============================================
# Load RSA Key
# ===============================================
def load_rsa_key(path: str):
    data = Path(path).read_bytes()

    # まず秘密鍵として試す（パスワード無し）
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        # たぶん暗号化されてる（password required）
        pw = getpass.getpass("Private key password: ").encode("utf-8")
        return serialization.load_pem_private_key(data, password=pw)
    except Exception:
        pass

    # 公開鍵として読む
    return serialization.load_pem_public_key(data)

# ===============================================
# RSA Encrypt / Decrypt Helper
# ===============================================
def rsa_encrypt_key(aes_key: bytes, pubkey):
    return pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(enc_key: bytes, privkey):
    try:
        return privkey.decrypt(
            enc_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        print("[ERROR] File is corrupted or the private key does not match.")
        print(traceback.format_exc())
        return None

# ===============================================
# RSA Encrypt / Decrypt
# ===============================================
def encrypt_with_blockchain(plaintext: bytes, user="unknown", memo="", key_path=None) -> bytes:
    if not key_path:
        print("[ERROR] No public key path provided for encryption.")
        return None
    pubkey = load_rsa_key(key_path)
    if hasattr(pubkey, "public_key"):  # If private key was mistakenly given
        pubkey = pubkey.public_key()

    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    enc_key = rsa_encrypt_key(aes_key, pubkey)
    file_hash = hashlib.sha256(ciphertext).hexdigest()

    core = (
        len(enc_key).to_bytes(4, "big") +
        enc_key + nonce + ciphertext + tag
    )
    return core

def decrypt_rsa_file(data: bytes, user="unknown", memo="") -> bytes:
    """
    Decrypts a file encrypted in RSA mode.
    Blockchain not supported.
    """
    try:
        klen = int.from_bytes(data[:4], "big")
    except Exception:
        print("[ERROR] Invalid file format.")
        return None

    try:
        enc_key = data[4:4+klen]
        pos = 4 + klen
        nonce = data[pos:pos+12]; pos += 12
        tag = data[-16:]
        ciphertext = data[pos:-16]

        privkey = load_rsa_key(RSA_KEY_PATH)
        aes_key = rsa_decrypt_key(enc_key, privkey)
        if aes_key is None:
            return None

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        file_hash = hashlib.sha256(ciphertext).hexdigest()
        #print(f"[INFO] Decrypted (hash={file_hash}, user={user}, memo={memo})")

        return plaintext

    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return None

# ===============================================
# File-Level Helpers
# ===============================================
def encrypt_file_with_dialog(file_path=None, pubkey=None):
    if not file_path:
        return None

    with open(file_path, "rb") as f:
        plaintext = f.read()

    user = getpass.getuser()
    memo = ""  # No GUI memo here in CUI mode

    data = encrypt_with_blockchain(plaintext, user=user, memo=memo, key_path=pubkey)
    if not data:
        return None

    out_path = file_path + ".rdec"
    with open(out_path, "wb") as out:
        out.write(data)

    print(f"[INFO] File encrypted: {out_path}")
    return out_path

def decrypt_file_with_dialog(file_path=None):
    if file_path is None:
        print("[ERROR] No file path provided for decryption.")
        return None

    with open(file_path, "rb") as f:
        blob = f.read()

    user = getpass.getuser()
    memo = ""  # No GUI memo here in CUI mode
    try:
        plaintext = decrypt_rsa_file(blob, user=user, memo=memo)
        if plaintext is None:
            return
    except TypeError:
        return None

    if file_path.endswith(".rdec"):
        out_path = file_path[:-5]
    else:
        out_path = file_path + ".dec"

    try:
        with open(out_path, "wb") as out:
            out.write(plaintext)
    except TypeError:
        return None

    print(f"[INFO] File decrypted: {out_path}")
    return out_path
