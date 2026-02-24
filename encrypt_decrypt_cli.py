import os
import sys
import base64
import warnings
import getpass
import tkinter as tk
from tkinter import simpledialog

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from getpass import GetPassWarning
warnings.simplefilter("ignore", GetPassWarning)

# ================================
# CONSTANTS
# ================================
ITERATIONS = 200000
CHUNK_SIZE = 1024 * 1024
BACKEND = default_backend()

# ================================
# INPUT NORMALIZATION
# ================================
def normalize_input(text):
    if not text:
        return text
    for a, b in {"“":'"',"”":'"',"‘":"'","’":"'"} .items():
        text = text.replace(a, b)
    return text.strip()

# ================================
# PATH RESOLUTION
# ================================
def resolve_path(path):
    path = normalize_input(path)
    if not os.path.dirname(path):
        print(f"ℹ Using current directory: {os.getcwd()}")
        return os.path.join(os.getcwd(), path)
    return path

# ================================
# OUTPUT FILE CHECK
# ================================
def warn_and_resolve_output(path):
    while os.path.exists(path):
        print("\n⚠ File already exists:")
        print(path)
        path = resolve_path(input("Enter new filename or full path: "))
    return path

# ================================
# PROGRESS BAR (FIXED)
# ================================
def print_progress(done, total):
    percent = int((done / total) * 100)
    bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
    print(f"\r[{bar}] {percent}%", end="", flush=True)

# ================================
# PASSWORD INPUT
# ================================
def get_password(prompt="Password: "):
    if sys.version_info[:2] <= (3, 12):
        try:
            return getpass.getpass(prompt)
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()
    pwd = simpledialog.askstring("Password Required", prompt, show="*")
    root.destroy()

    if not pwd:
        print("❌ Password required.")
        sys.exit(1)

    return pwd

# ================================
# KEY DERIVATION
# ================================
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND,
    )
    return kdf.derive(password.encode())

# ================================
# AES ENCRYPT / DECRYPT
# ================================
def aes_encrypt(data, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return salt + iv + encrypted

def aes_decrypt(raw, password):
    salt, iv, encrypted = raw[:16], raw[16:32], raw[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    padded = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ================================
# FILE ENCRYPT / DECRYPT
# ================================
def encrypt_file(path, password):
    path = resolve_path(path)
    if not os.path.isfile(path):
        print("❌ File not found:", path)
        return

    out_path = warn_and_resolve_output(path + ".enc")
    size = os.path.getsize(path)
    processed = 0
    buffer = b""

    print("🔐 Encrypting...")
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            buffer += chunk
            processed += len(chunk)
            print_progress(processed, size)

    with open(out_path, "wb") as f:
        f.write(base64.b64encode(aes_encrypt(buffer, password)))

    print("\n✅ Encrypted →", out_path)

def decrypt_file(enc_path, password):
    enc_path = resolve_path(enc_path)
    if not os.path.isfile(enc_path):
        print("❌ File not found:", enc_path)
        return

    raw = b""
    size = os.path.getsize(enc_path)
    processed = 0

    print("🔓 Decrypting...")
    with open(enc_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            raw += chunk
            processed += len(chunk)
            print_progress(processed, size)

    try:
        decrypted = aes_decrypt(base64.b64decode(raw), password)
    except Exception:
        print("\n❌ Wrong password.")
        return

    out = resolve_path(input("\nOutput filename: "))
    out = warn_and_resolve_output(out)

    with open(out, "wb") as f:
        f.write(decrypted)

    print("✅ Decrypted →", out)

# ================================
# TEXT ENCRYPT / DECRYPT (PRINTS CORRECTLY)
# ================================
def encrypt_text(text, password):
    return base64.b64encode(aes_encrypt(text.encode(), password)).decode()

def decrypt_text(text, password):
    try:
        return aes_decrypt(base64.b64decode(text), password).decode()
    except Exception:
        return "❌ Decryption failed"

# ================================
# MENU
# ================================
def menu():
    print("\n========= Secure Encryptor =========")
    print("1. Encrypt file")
    print("2. Decrypt file")
    print("3. Encrypt text")
    print("4. Decrypt text")
    print("5. Exit")

def main():
    while True:
        menu()
        choice = input("Choose (1-5): ")

        if choice == "1":
            encrypt_file(input("File: "), get_password())
        elif choice == "2":
            decrypt_file(input("Encrypted file: "), get_password())
        elif choice == "3":
            print("\nEncrypted text:\n", encrypt_text(input("Text: "), get_password()))
        elif choice == "4":
            print("\nDecrypted text:\n", decrypt_text(input("Encrypted text: "), get_password()))
        elif choice == "5":
            break
        else:
            print("❌ Invalid option")

# ✅ FIXED ENTRY POINT
if __name__ == "__main__":
    main()
