# ========= trusted keys utils =========
import os, hashlib
#from tkinter import ttk, messagebox
from Crypto.PublicKey import RSA
#import tkinter as tk
#from tkinter import ttk, messagebox

def _default_app_dir() -> str:
    base = os.getenv("APPDATA") or os.path.expanduser("~")
    folder = os.path.join(base, "EncryptSecureDEC")
    os.makedirs(folder, exist_ok=True)
    return folder

default_keys=_default_app_dir()+"\\key"

def _trusted_dir() -> str:
    # default_keys = ".../EncryptSecureDEC/Key" を想定
    app_dir = os.path.dirname(default_keys)     # ".../EncryptSecureDEC"
    d = os.path.join(app_dir, "TrustedKeys")
    os.makedirs(d, exist_ok=True)
    return d

def _sha256_fp(pem_bytes: bytes) -> str:
    h = hashlib.sha256(pem_bytes).hexdigest()
    return ":".join(h[i:i+2] for i in range(0, 40, 2))  # 表示用短縮（20バイト）

def list_trusted_keys() -> list[dict]:
    """UI表示用の辞書リスト: [{label, path, bits, fp}]"""
    items = []
    tdir = _trusted_dir()
    for fn in os.listdir(tdir):
        if not fn.lower().endswith(".pem"): 
            continue
        p = os.path.join(tdir, fn)
        try:
            with open(p, "rb") as f:
                pem = f.read()
            key = RSA.import_key(pem)
            items.append({
                "label": os.path.splitext(fn)[0],
                "path": p,
                "bits": key.size_in_bits(),
                "fp": _sha256_fp(key.export_key(format="PEM")),
            })
        except Exception:
            # 壊れた鍵などはスキップ
            continue
    # ラベル昇順
    items.sort(key=lambda x: x["label"].lower())
    return items

def delete_trusted_key(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except Exception:
        return False
# =====================================

def open_trusted_keys_manager(parent_window=None):
    mgr = tk.Toplevel(parent_window)
    mgr.title("信頼済み公開鍵")
    try:
        mgr.iconbitmap('resources/IMG_8776.ICO')
    except Exception:
        pass
    mgr.resizable(False, False)
    mgr.columnconfigure(0, weight=1)
    mgr.rowconfigure(1, weight=1)

    # タイトル
    ttk.Label(mgr, text="信頼済み公開鍵一覧", font=("", 12, "bold"))\
        .grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

    # Treeview
    cols = ("label", "bits", "fp", "path")
    tv = ttk.Treeview(mgr, columns=cols, show="headings", height=10)
    tv.grid(row=1, column=0, sticky="nsew", padx=12)

    tv.heading("label", text="ラベル")
    tv.heading("bits", text="鍵長")
    tv.heading("fp", text="フィンガープリント(SHA-256)")
    tv.heading("path", text="保存場所")

    tv.column("label", width=180, anchor="w")
    tv.column("bits", width=70, anchor="center")
    tv.column("fp", width=260, anchor="w")
    tv.column("path", width=380, anchor="w")

    # スクロールバー
    yscroll = ttk.Scrollbar(mgr, orient="vertical", command=tv.yview)
    yscroll.grid(row=1, column=1, sticky="ns")
    tv.configure(yscrollcommand=yscroll.set)

    # ボタン列
    btn_row = ttk.Frame(mgr)
    btn_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 12))
    btn_row.columnconfigure(0, weight=1)

    btn_delete = ttk.Button(btn_row, text="削除")
    btn_open   = ttk.Button(btn_row, text="フォルダを開く")
    btn_reload = ttk.Button(btn_row, text="再読込")
    btn_close  = ttk.Button(btn_row, text="閉じる", command=mgr.destroy)

    btn_delete.grid(row=0, column=1, padx=(0,6), sticky="e")
    btn_open.grid(row=0, column=2, padx=(0,6), sticky="e")
    btn_reload.grid(row=0, column=3, padx=(0,6), sticky="e")
    btn_close.grid(row=0, column=4, sticky="e")

    # データ投入
    def refresh():
        tv.delete(*tv.get_children())
        for item in list_trusted_keys():
            tv.insert("", "end", values=(item["label"], f'{item["bits"]} bit', item["fp"], item["path"]))
        _update_buttons()

    # 選択状態でボタン有効化
    def _update_buttons(_evt=None):
        sel = tv.selection()
        state = "normal" if sel else "disabled"
        btn_delete.config(state=state)
        btn_open.config(state=state)

    tv.bind("<<TreeviewSelect>>", _update_buttons)

    # 削除処理
    def on_delete():
        sel = tv.selection()
        if not sel: return
        vals = tv.item(sel[0], "values")
        label, _, _, path = vals
        if messagebox.askyesno("確認", f"「{label}」を削除しますか？", parent=mgr):
            if delete_trusted_key(path):
                messagebox.showinfo("削除", "削除しました。", parent=mgr)
                refresh()
            else:
                messagebox.showerror("エラー", "削除に失敗しました。", parent=mgr)

    btn_delete.config(command=on_delete)

    # フォルダを開く
    def on_open_folder():
        sel = tv.selection()
        if not sel: return
        import sys, subprocess
        vals = tv.item(sel[0], "values")
        folder = os.path.dirname(vals[3])
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore
            elif sys.platform == "darwin":
                subprocess.call(["open", folder])
            else:
                subprocess.call(["xdg-open", folder])
        except Exception:
            messagebox.showerror("エラー", "フォルダを開けませんでした。", parent=mgr)

    btn_open.config(command=on_open_folder)

    btn_reload.config(command=refresh)
    refresh()




import sys
import os
import tarfile
import tempfile

import esdcompress

def safe_extract(tar: tarfile.TarFile, path: str):
    # test_folder_gui.py と同じ安全対策（パストラバーサル防止）
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not os.path.realpath(member_path).startswith(os.path.realpath(path)):
            raise Exception("Unsafe tar file detected")

    tar.extractall(path=path, filter="data")

def decrypt_folder_cli(in_path: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = os.path.join(tmp, "restore.tar")

            # esdc → tar（出力ファイルは temp の中なので権限で死ににくい）
            esdcompress.decompress_file(in_path, tar_path, allow_partial=False)

            # tar → フォルダ
            with tarfile.open(tar_path, "r") as tar:
                safe_extract(tar, out_dir)
        return 1
    except Exception as e:
        return str(e)
    
def encrypt_folder(path,out_path):
        folder = path
        
        base_name = os.path.basename(folder.rstrip("/\\"))

        try:
            with tempfile.TemporaryDirectory() as tmp:
                tar_path = os.path.join(tmp, f"{base_name}.tar")

                # フォルダ → tar
                with tarfile.open(tar_path, "w") as tar:
                    tar.add(folder, arcname=base_name)

                # tar → esdc
                esdcompress.compress_file(tar_path, out_path)

            return 1

        except Exception as e:
            return str(e)
