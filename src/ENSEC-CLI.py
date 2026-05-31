# Copyright (c) 2025 合同会社Anvelk Innovations. All Rights Reserved.

import argparse
import os
import getpass
import sys
import lzma
import hashlib
import json
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import rsa_signer
import wavencode
import rsa_encryptor
from conf_load import load_config
from pathlib import Path

conf = load_config()

# OKならそのまま続行

BLOCKCHAIN_HEADER = b'BLOCKCHAIN_DATA_START\n'
def _format_bytes(num: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num)
    for u in units:
        if n < 1024.0 or u == units[-1]:
            return f"{n:.2f} {u}" if u != "B" else f"{int(n)} {u}"
        n /= 1024.0

def _dir_size_bytes(root: str) -> int:
    total = 0
    # シンボリックリンクは辿らない（無限ループ回避）
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                    except (PermissionError, FileNotFoundError):
                        # 権限/競合で読めないものはスキップ
                        continue
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            continue
    return total

class Block:
    def __init__(self, data, previous_hash, operation_type, file_hash, user, memo):
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.data = data
        self.previous_hash = previous_hash
        self.operation_type = operation_type
        self.file_hash = file_hash
        self.user = user
        self.memo = memo
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(
            str(self.timestamp).encode('utf-8') +
            str(self.data).encode('utf-8') +
            str(self.previous_hash).encode('utf-8') +
            str(self.operation_type).encode('utf-8') +
            str(self.file_hash).encode('utf-8') +
            str(self.user).encode('utf-8') +
            str(self.memo).encode('utf-8')
        )
        return sha.hexdigest()

    def to_dict(self):
        return {
            'timestamp': str(self.timestamp),
            'data': self.data,
            'previous_hash': self.previous_hash,
            'operation_type': self.operation_type,
            'file_hash': self.file_hash,
            'user': self.user,
            'memo': self.memo,
            'hash': self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, new_block):
        if len(self.chain) == 0:
            new_block.previous_hash = "0"
        else:
            new_block.previous_hash = self.chain[-1].hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def to_json(self):
        return json.dumps([block.to_dict() for block in self.chain], indent=2)

    @staticmethod
    def from_json(data):
        chain_data = json.loads(data)
        blockchain = Blockchain()
        for block_data in chain_data:
            block = Block(
                data=block_data['data'],
                previous_hash=block_data['previous_hash'],
                operation_type=block_data['operation_type'],
                file_hash=block_data['file_hash'],
                user=block_data['user'],
                memo=block_data['memo']
            )
            block.timestamp = datetime.datetime.strptime(block_data['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z')
            block.hash = block_data['hash']
            blockchain.chain.append(block)
        return blockchain

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                return False
            if current.calculate_hash() != current.hash:
                return False
        return True

deletemode = {
    "mode": False
}

def delete_pre_file(file_path):
    path_o = Path(file_path)
    abs_path = path_o.resolve()
    if abs_path.exists():
        abs_path.unlink()

def cli_encrypt(file_path, password, memo):
    import passchk 
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    salt = get_random_bytes(16)
    
    if passchk.passchk(memo, password):
        print(" Warning: The note contains a password.\n For security reasons, it is recommended not to include passwords in notes.")
        a = input(" Do you want to continue (y or n) >> ")
        if a.lower() != "y":
            print(" Canceled the encryption.")
            return 
        
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    file_hash = hashlib.sha256(ciphertext).hexdigest()
    username = getpass.getuser()

    try:
        with lzma.open(file_path + ".vdec", 'rb') as f:
            data = f.read()
        split_index = data.index(BLOCKCHAIN_HEADER)
        chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
        blockchain = Blockchain.from_json(chain_json)
    except:
        blockchain = Blockchain()
    block = Block(file_hash, blockchain.chain[-1].hash if blockchain.chain else "0", "Encrypt", file_hash, username, memo)
    blockchain.add_block(block)

    encrypted_data = salt + nonce + ciphertext + tag
    blockchain_data = BLOCKCHAIN_HEADER + blockchain.to_json().encode('utf-8')

    out_path = file_path + ".vdec"
    with lzma.open(out_path, 'wb') as f:
        f.write(encrypted_data)
        f.write(blockchain_data)
    if deletemode["mode"] == True:
        delete_pre_file(file_path)
    print(f"✅ Encryption completed: {out_path}")

def cli_decrypt(file_path, password, memo):
    if file_path.endswith(".wav"):
        with open(file_path, 'rb') as f:
            wav_bytes = f.read()
        data = wavencode.wav_bytes_to_binary(wav_bytes)
    else:
        with lzma.open(file_path, 'rb') as f:
            data = f.read()

    split_index = data.index(BLOCKCHAIN_HEADER)
    crypto_data = data[:split_index]
    chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
    blockchain = Blockchain.from_json(chain_json)

    salt = crypto_data[:16]
    nonce = crypto_data[16:28]
    tag = crypto_data[-16:]
    ciphertext = crypto_data[28:-16]

    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("❌ Error: Decryption failed. The password may be incorrect or the file may be tampered with.")
        sys.exit(1)
    if conf==True:
        output_file = file_path.replace(".vdec.wav", "_decrypted").replace(".vdec", "_decrypted")
    else:
        output_file = file_path.replace(".vdec.wav", "").replace(".vdec", "")
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    username = getpass.getuser()
    file_hash = hashlib.sha256(ciphertext).hexdigest()
    block = Block(file_hash, blockchain.chain[-1].hash if blockchain.chain else "0", "Decrypt", file_hash, username, memo)
    blockchain.add_block(block)

    if not file_path.endswith(".wav"):
        with lzma.open(file_path, 'wb') as f:
            f.write(salt + nonce + ciphertext + tag)
            f.write(BLOCKCHAIN_HEADER)
            f.write(blockchain.to_json().encode('utf-8'))

    print(f"✅ Decryption completed: {output_file}")

def cli_verify_chain(file_path):
    if file_path.endswith(".wav"):
        with open(file_path, 'rb') as f:
            data = wavencode.wav_bytes_to_binary(f.read())
    else:
        with lzma.open(file_path, 'rb') as f:
            data = f.read()
    split_index = data.index(BLOCKCHAIN_HEADER)
    chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
    blockchain = Blockchain.from_json(chain_json)
    if blockchain.is_chain_valid():
        print("✅ Blockchain is consistent")
    else:
        print("❌ Blockchain has inconsistencies")

# --- RSA key check at startup ---
rsa_encryptor.ensure_rsa_keys()
from utils import decrypt_folder_cli,encrypt_folder

def main():
    parser = argparse.ArgumentParser(description="EncryptSecureDEC CLI")
    parser.add_argument("mode",choices=["encrypt","decrypt","verify-chain","sign",
                                        "verify-sign","key-protect-on","key-protect-off"])
    parser.add_argument("file", help="Target file path")
    parser.add_argument("--memo", default="", help="Operation memo")
    parser.add_argument("--password", help="Password for encryption/decryption (prompted if omitted)")
    parser.add_argument("--delete", action="store_true",help="Delete the plaintext file after encrypting the file.")
    parser.add_argument("--rsa", action="store_true",help="Encrypt / Decrypt RSA Mode")
    parser.add_argument("--dir", action="store_true",help="Encrypt Dir mode")
    parser.add_argument("--pubkey", help="Path to public key file (only required in RSA encrypt mode)")
    args = parser.parse_args()

    # --- validate RSA/pubkey usage ---
        # --- validate RSA/pubkey usage ---
    if args.rsa:
        if args.mode == "decrypt" and args.pubkey:
            parser.error("--pubkey must not be specified in decrypt mode (private key is used automatically)")
    file_path = Path(args.file)
    ext = file_path.suffix

    # --- RSA Key Protection Management ---
    if args.mode == "key-protect-on":
        result = rsa_encryptor.migrate_private_key_encrypt_inplace()
        if result == 0:
            print("🔐 Private key protection ENABLED")
        sys.exit(result)

    if args.mode == "key-protect-off":
        result = rsa_encryptor.migrate_private_key_decrypt_inplace()
        if result == 0:
            print("🔓 Private key protection DISABLED")
        sys.exit(result)

    if not args.rsa and ext != ".rdec" and args.mode != "sign" and args.mode != "verify-sign" and args.dir!=True and ext!=".esdc":
        password = args.password or getpass.getpass("🔑 Enter password: ")

    # Check if file exists
    if not os.path.isfile(args.file) and args.dir!=True:
        print(f"❌ Error: File not found - {args.file}")
        sys.exit(1)

    # For decrypt mode, check extension
    if args.mode == "decrypt" and not (args.file.endswith(".vdec") or args.file.endswith(".rdec") or args.file.endswith(".esdc")):
        print(f"❌ Error: The file for decryption must have a '.vdec' or '.rdec' extension.")
        sys.exit(1)

    if args.delete:
        deletemode["mode"] = True

    if args.mode=="decrypt" and os.path.splitext(args.file)[1].lower()==".esdc":
        if os.path.splitext(args.file)[1].lower()==".esdc":
            if os.path.exists(args.file)==False:
                print("Decryption failed: Failed to decrypt\n file not found")
                sys.exit(1)
            p =  file_path

            # 「そのパスが属するディレクトリ」を取りたい場合
            parent_dir = p.parent
            # ルート判定（E:\ や C:\ など）
            is_root = parent_dir == Path(parent_dir.anchor)

            if is_root:
                # ルート直下に作業用フォルダを作る（例: E:\_esdwork）
                work_dir = parent_dir / "_esdwork"
            else:
                work_dir = parent_dir / "_esdwork"  # どのみちサブフォルダに逃がすと安全
            work_dir.mkdir(parents=True, exist_ok=True)
            
            res=decrypt_folder_cli(args.file,work_dir)
            if res==1:
                print("Decryption successful: Decryption was successful\n")
            else:
                print(f"Decryption failed: Failed to decrypt\n {res}")
            sys.exit()
    if args.mode=="encrypt" and args.dir==True:
        if os.path.exists(args.file)==False:
            print("Encryption failed: Failed to encrypt\n Dir not Found")
            sys.exit(1)
        # ルート判定（E:\ や C:\ など）
        folder_path = Path(args.file).resolve()
        parent_dir = folder_path.parent
        base_name = folder_path.name
        
        size_bytes = _dir_size_bytes(str(folder_path))
        print(f"📦 Folder size: {_format_bytes(size_bytes)} ({size_bytes:,} bytes)")

        out_file = str(parent_dir / f"{base_name}.esdc")
        res=encrypt_folder(args.file,out_file)
        if res==1:
            print("Encryption successful: Encryption was successful\n")
        else:
            print(f"Encryption failed: Failed to encrypt\n {res}")
        sys.exit(0)
    
    # --- RSA Mode ---
    if args.rsa and args.mode == "encrypt":
        pubkey_path = args.pubkey if args.pubkey else str(rsa_encryptor.RSA_PUB_PATH)
        rsa_encryptor.encrypt_file_with_dialog(args.file, pubkey_path)
        sys.exit()
    elif args.rsa and args.mode == "decrypt":
        rsa_encryptor.decrypt_file_with_dialog(args.file)
        sys.exit()

    # --- Password Mode ---
    if args.mode == "encrypt":
        cli_encrypt(args.file, password, args.memo)
    elif args.mode == "decrypt":
        cli_decrypt(args.file, password, args.memo)
    elif args.mode == "verify-chain":
        cli_verify_chain(args.file)
    elif args.mode == "sign":
        rsa_signer.sign_file(args.file)
    elif args.mode == "verify-sign":
        rsa_signer.verify_file_signature(args.file)
    else:
        print("❌ Unknown mode")

if __name__ == "__main__":
    main()
