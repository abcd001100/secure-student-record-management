"""
storage_paths.py
-----------------
Central place for the two files the application persists to disk:

  students.db     the SQLite database (contains ciphertext, never
                   plaintext sensitive fields, and never any key).
  keystore.json    the wrapped Data Encryption Key. This file is safe
                   to back up on its own -- without the correct master
                   password it cannot be unwrapped -- but it must never
                   be committed to a public report or repository next
                   to the master password itself.
"""

import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "students.db")
KEYSTORE_PATH = os.path.join(BASE_DIR, "keystore.json")


def keystore_exists() -> bool:
    return os.path.exists(KEYSTORE_PATH)


def load_keystore() -> dict:
    with open(KEYSTORE_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_keystore(keystore: dict) -> None:
    with open(KEYSTORE_PATH, "w", encoding="utf-8") as fh:
        json.dump(keystore, fh, indent=2)
