#!/usr/bin/env python3
"""
File Protection Utility (task4)
Encrypts a file with a password and restores it on demand.

Requires: pip install cryptography

Usage:
    python file_protect.py protect  secret.txt            # -> secret.txt.locked
    python file_protect.py restore  secret.txt.locked     # -> secret.txt
    python file_protect.py restore  secret.txt.locked -o out.txt
"""

import argparse
import base64
import getpass
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"FPU1"          # file signature / format version
SALT_SIZE = 16
ITERATIONS = 480_000
EXT = ".locked"


def derive_key(password: str, salt: bytes) -> bytes:
    """Turn a password into a Fernet key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def protect(path: str, password: str) -> str:
    with open(path, "rb") as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(data)

    out_path = path + EXT
    with open(out_path, "wb") as f:
        f.write(MAGIC + salt + token)
    return out_path


def restore(path: str, password: str, out_path: str | None = None) -> str:
    with open(path, "rb") as f:
        blob = f.read()

    if not blob.startswith(MAGIC):
        raise ValueError("Not a file created by this utility.")

    salt = blob[len(MAGIC): len(MAGIC) + SALT_SIZE]
    token = blob[len(MAGIC) + SALT_SIZE:]

    try:
        data = Fernet(derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise PermissionError("Wrong password or the file has been tampered with.")

    if out_path is None:
        out_path = path[:-len(EXT)] if path.endswith(EXT) else path + ".restored"

    if os.path.exists(out_path):
        raise FileExistsError(f"'{out_path}' already exists; use -o to choose another name.")

    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def get_password(confirm: bool) -> str:
    pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("Error: password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        sys.exit("Error: passwords do not match.")
    return pw


def main():
    parser = argparse.ArgumentParser(description="File Protection Utility")
    parser.add_argument("action", choices=["protect", "restore"])
    parser.add_argument("file")
    parser.add_argument("-o", "--output", help="output path (restore only)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        sys.exit(f"Error: '{args.file}' not found.")

    try:
        if args.action == "protect":
            out = protect(args.file, get_password(confirm=True))
            print(f"Protected file saved as: {out}")
        else:
            out = restore(args.file, get_password(confirm=False), args.output)
            print(f"File restored as: {out}")
    except (ValueError, PermissionError, FileExistsError) as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
