"""
crypto_utils.py
----------------
All cryptographic operations for the Secure Student Record Management
system live in this module. Nothing outside this file is allowed to
touch a raw key, so the rest of the application only ever calls the
functions defined here.

Two independent cryptographic mechanisms are used:

1. Password hashing (for user login credentials)
   - PBKDF2-HMAC-SHA256 with a random 16-byte salt per user and
     600,000 iterations (meeting OWASP's current minimum recommendation
     for PBKDF2-HMAC-SHA256; OWASP Foundation, n.d.-a). This never uses
     the same secret as the data encryption key below -- a login
     password only proves who you are, it does not by itself decrypt
     anything.

2. Envelope encryption (for student record confidentiality)
   - A single random 256-bit Data Encryption Key (DEK) is generated
     once when the system is first installed. The DEK is the key that
     actually encrypts every student record with AES-256-GCM.
   - The DEK itself is never stored in plaintext. It is "wrapped"
     (encrypted) with a Key Encryption Key (KEK) that is derived from
     an administrator-chosen master password using PBKDF2-HMAC-SHA256
     with 600,000 iterations. The wrapped DEK, together with the salt
     and nonce needed to reproduce the KEK and unwrap it, is stored in
     keystore.json.
   - Every time the application starts, the administrator must supply
     the master password. If it is correct, AES-GCM successfully
     unwraps the DEK and the DEK is held only in memory for the
     lifetime of the running process. If the master password is
     wrong, AES-GCM's authentication tag check fails (InvalidTag) and
     the DEK is never recovered.

AES-GCM was chosen (rather than AES-CBC + a separate HMAC) because it
is an AEAD (Authenticated Encryption with Associated Data) cipher: a
single operation provides both confidentiality and integrity, and the
"associated data" parameter is used to cryptographically bind each
ciphertext to the student record it belongs to, so a ciphertext copied
from one record into another is rejected during decryption.
"""

from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Tunable security parameters
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS_PASSWORD = 600_000   # for user login passwords (OWASP, n.d.-a minimum)
PBKDF2_ITERATIONS_KEK = 600_000        # for the master-password-derived KEK
SALT_SIZE = 16                         # bytes
NONCE_SIZE = 12                        # bytes; recommended size for AES-GCM
DEK_SIZE = 32                          # bytes = 256 bits (AES-256)
KEYSTORE_AAD = b"secure-student-records-dek-v1"


class CryptoError(Exception):
    """Raised whenever a cryptographic check fails (wrong password,
    tampered ciphertext, or a ciphertext/record mismatch)."""


def _pbkdf2(secret: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret)


# ---------------------------------------------------------------------------
# 1. Password hashing (login credentials)
# ---------------------------------------------------------------------------

@dataclass
class PasswordHash:
    salt_b64: str
    hash_b64: str
    iterations: int


def hash_password(password: str) -> PasswordHash:
    """Derive a storable password hash. Never store the raw password."""
    salt = os.urandom(SALT_SIZE)
    digest = _pbkdf2(password.encode("utf-8"), salt, PBKDF2_ITERATIONS_PASSWORD)
    return PasswordHash(
        salt_b64=base64.b64encode(salt).decode("ascii"),
        hash_b64=base64.b64encode(digest).decode("ascii"),
        iterations=PBKDF2_ITERATIONS_PASSWORD,
    )


def verify_password(password: str, salt_b64: str, hash_b64: str, iterations: int) -> bool:
    """Recompute the PBKDF2 digest and compare it in constant time."""
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    actual = _pbkdf2(password.encode("utf-8"), salt, iterations, length=len(expected))
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# 2. Envelope encryption: master password -> KEK -> unwrap DEK
# ---------------------------------------------------------------------------

def create_keystore(master_password: str) -> dict:
    """Called exactly once, on first run, to create a brand-new DEK and
    wrap it under a KEK derived from the chosen master password."""
    salt = os.urandom(SALT_SIZE)
    kek = _pbkdf2(master_password.encode("utf-8"), salt, PBKDF2_ITERATIONS_KEK, DEK_SIZE)
    dek = os.urandom(DEK_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    wrapped_dek = AESGCM(kek).encrypt(nonce, dek, KEYSTORE_AAD)
    return {
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "salt": base64.b64encode(salt).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS_KEK,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode("ascii"),
    }


def unlock_keystore(master_password: str, keystore: dict) -> bytes:
    """Derive the KEK from the supplied master password and use it to
    unwrap (decrypt) the DEK. Raises CryptoError if the master password
    is wrong or the keystore file has been tampered with."""
    try:
        salt = base64.b64decode(keystore["salt"])
        kek = _pbkdf2(master_password.encode("utf-8"), salt, keystore["iterations"], DEK_SIZE)
        nonce = base64.b64decode(keystore["nonce"])
        wrapped_dek = base64.b64decode(keystore["wrapped_dek"])
        dek = AESGCM(kek).decrypt(nonce, wrapped_dek, KEYSTORE_AAD)
    except (InvalidTag, KeyError, ValueError) as exc:
        raise CryptoError("Incorrect master password or corrupted keystore.") from exc
    return dek


def change_master_password(old_password: str, new_password: str, keystore: dict) -> dict:
    """Re-wrap the existing DEK under a new KEK, without ever changing
    the DEK itself (so already-encrypted records remain readable)."""
    dek = unlock_keystore(old_password, keystore)
    salt = os.urandom(SALT_SIZE)
    kek = _pbkdf2(new_password.encode("utf-8"), salt, PBKDF2_ITERATIONS_KEK, DEK_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    wrapped_dek = AESGCM(kek).encrypt(nonce, dek, KEYSTORE_AAD)
    return {
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "salt": base64.b64encode(salt).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS_KEK,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# 3. Per-record AES-256-GCM encryption of sensitive student fields
# ---------------------------------------------------------------------------

def encrypt_record(dek: bytes, record_aad: str, plaintext: bytes) -> tuple[str, str]:
    """Encrypt one record's sensitive-field JSON blob.

    record_aad (Associated Data) is the record's own student ID. It is
    authenticated but not encrypted, and it cryptographically binds this
    ciphertext to that specific student record: pasting the ciphertext
    into a different record's row will fail to decrypt.
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, record_aad.encode("utf-8"))
    return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ciphertext).decode("ascii")


def decrypt_record(dek: bytes, record_aad: str, nonce_b64: str, ciphertext_b64: str) -> bytes:
    """Decrypt and authenticate one record's sensitive-field JSON blob.
    Raises CryptoError if the DEK is wrong, the ciphertext was modified,
    or record_aad does not match the value used at encryption time."""
    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        return AESGCM(dek).decrypt(nonce, ciphertext, record_aad.encode("utf-8"))
    except (InvalidTag, ValueError) as exc:
        raise CryptoError(
            "Integrity check failed: wrong key, tampered data, or mismatched record."
        ) from exc
