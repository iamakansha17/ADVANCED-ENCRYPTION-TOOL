import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

MAGIC = b'AE01'   # file magic/version
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000  # PBKDF2 iterations (tunable)


def derive_key(password: bytes, salt: bytes, iterations: int = KDF_ITERS) -> bytes:
    """Derive a 32-byte AES key from password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(password: str, in_path: str, out_path: str = None) -> str:
    """Encrypt a file using AES-256-GCM and write output. Returns output path."""
    if out_path is None:
        out_path = in_path + ".enc"

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password.encode('utf-8'), salt)

    aesgcm = AESGCM(key)

    # read plaintext
    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # file layout: MAGIC | salt | nonce | ciphertext
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    return out_path


def decrypt_file(password: str, in_path: str, out_path: str = None) -> str:
    """Decrypt a file produced by encrypt_file. Returns output path."""
    with open(in_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Unrecognized file format / magic")

        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key = derive_key(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    if out_path is None:
        # strip .enc if present
        if in_path.endswith(".enc"):
            out_path = in_path[:-4] + ".dec"
        else:
            out_path = in_path + ".dec"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    return out_path


# --------------------------
# Simple Tkinter GUI
# --------------------------
class EncryptGUI:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Encryption Tool (AES-256-GCM)")

        # Input file
        self.in_label = tk.Label(root, text="Input file:")
        self.in_label.grid(row=0, column=0, sticky="e")
        self.in_entry = tk.Entry(root, width=60)
        self.in_entry.grid(row=0, column=1, padx=5, pady=5)
        self.in_btn = tk.Button(root, text="Browse", command=self.browse_input)
        self.in_btn.grid(row=0, column=2, padx=5)

        # Password
        self.pw_label = tk.Label(root, text="Password:")
        self.pw_label.grid(row=1, column=0, sticky="e")
        self.pw_entry = tk.Entry(root, width=60, show="*")
        self.pw_entry.grid(row=1, column=1, padx=5, pady=5)

        # Action buttons
        self.encrypt_btn = tk.Button(root, text="Encrypt", width=20, command=self.encrypt_action)
        self.encrypt_btn.grid(row=2, column=0, padx=5, pady=10)
        self.decrypt_btn = tk.Button(root, text="Decrypt", width=20, command=self.decrypt_action)
        self.decrypt_btn.grid(row=2, column=1, padx=5, pady=10, sticky="w")

        # Info / status
        self.status = tk.Label(root, text="Ready", anchor="w")
        self.status.grid(row=3, column=0, columnspan=3, sticky="we", padx=5, pady=5)

    def browse_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.in_entry.delete(0, tk.END)
            self.in_entry.insert(0, path)

    def encrypt_action(self):
        in_path = self.in_entry.get().strip()
        pw = self.pw_entry.get()
        if not in_path or not pw:
            messagebox.showwarning("Missing", "Please provide input file and password.")
            return
        try:
            out = encrypt_file(pw, in_path)
            messagebox.showinfo("Success", f"Encrypted → {out}")
            self.status.config(text=f"Encrypted: {out}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
            self.status.config(text=f"Error: {e}")

    def decrypt_action(self):
        in_path = self.in_entry.get().strip()
        pw = self.pw_entry.get()
        if not in_path or not pw:
            messagebox.showwarning("Missing", "Please provide input file and password.")
            return
        try:
            out = decrypt_file(pw, in_path)
            messagebox.showinfo("Success", f"Decrypted → {out}")
            self.status.config(text=f"Decrypted: {out}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            self.status.config(text=f"Error: {e}")


# --------------------------
# CLI helper for users who want to use command-line
# --------------------------
def cli_help():
    print("Advanced Encryption Tool - CLI usage")
    print("Encrypt: python advanced_encryption_tool.py enc <password> <infile> [outfile]")
    print("Decrypt: python advanced_encryption_tool.py dec <password> <infile> [outfile]")


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2:
        # CLI mode
        mode = sys.argv[1].lower()
        if mode == "enc" and len(sys.argv) >= 4:
            pw = sys.argv[2]
            inp = sys.argv[3]
            out = sys.argv[4] if len(sys.argv) >= 5 else None
            try:
                outp = encrypt_file(pw, inp, out)
                print("Encrypted ->", outp)
            except Exception as e:
                print("Error:", e)
        elif mode == "dec" and len(sys.argv) >= 4:
            pw = sys.argv[2]
            inp = sys.argv[3]
            out = sys.argv[4] if len(sys.argv) >= 5 else None
            try:
                outp = decrypt_file(pw, inp, out)
                print("Decrypted ->", outp)
            except Exception as e:
                print("Error:", e)
        else:
            cli_help()
    else:
        # Start GUI
        root = tk.Tk()
        app = EncryptGUI(root)
        root.mainloop()
