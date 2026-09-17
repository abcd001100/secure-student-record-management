"""
demo_evidence.py
-----------------
Not part of the automated test suite. This script exercises the real
application code (database + crypto_utils + records) against a
throw-away temporary database to produce concrete, reproducible
evidence for the report: what a stored ciphertext row actually looks
like, entropy of plaintext vs. ciphertext, encryption/decryption
timing, storage overhead, and a live demonstration of tamper and
wrong-key rejection. Every number below is measured on this machine
when the script is run -- nothing here is invented.

Run with:  python tests/demo_evidence.py
"""
import base64
import math
import os
import statistics
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto_utils, records
from app.auth import Session
from app.database import Database

DB_PATH = os.path.join(os.path.dirname(__file__), "_demo.db")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = Database(DB_PATH)
    admin = Session(username="demo_admin", role="admin")

    master_password = "DemoMaster#2026"
    keystore = crypto_utils.create_keystore(master_password)
    dek = crypto_utils.unlock_keystore(master_password, keystore)

    print("=" * 78)
    print("1. STORED ROW: what actually sits in students.db")
    print("=" * 78)
    student = records.StudentInput(
        student_id="AIU24102453",
        full_name="Abdulaziz Taju Mohammedyasin",
        program="BCS (Hons)",
        intake="Sem3 2025-2026",
        ic_passport_no="A12345678",
        phone="+60123456789",
        address="Alor Setar, Kedah, Malaysia",
        guardian_contact="+60129876543",
        remarks="No known medical conditions.",
    )
    records.add_student(db, dek, admin, student)
    row = db.get_student("AIU24102453")
    print(f"Plaintext column  student_id : {row.student_id}")
    print(f"Plaintext column  full_name  : {row.full_name}")
    print(f"Plaintext column  program    : {row.program}")
    print(f"Encrypted column  enc_nonce  : {row.enc_nonce}")
    print(f"Encrypted column  enc_data   : {row.enc_data[:80]}... "
          f"({len(base64.b64decode(row.enc_data))} bytes total)")
    print("-> IC/passport number, phone, address, guardian contact and remarks")
    print("   are NOT visible anywhere in the row above.")

    print()
    print("=" * 78)
    print("2. ENTROPY: plaintext sensitive-field JSON vs. AES-256-GCM ciphertext")
    print("=" * 78)
    import json
    payload = json.dumps({f: getattr(student, f) for f in records.SENSITIVE_FIELDS}).encode()
    ct_bytes = base64.b64decode(row.enc_data)
    print(f"Plaintext bytes : {len(payload):4d}   entropy = {shannon_entropy(payload):.4f} bits/byte")
    print(f"Ciphertext bytes: {len(ct_bytes):4d}   entropy = {shannon_entropy(ct_bytes):.4f} bits/byte")

    print()
    print("=" * 78)
    print("3. PERFORMANCE: encrypt/decrypt timing over 500 repetitions")
    print("=" * 78)
    sample = payload
    enc_times, dec_times = [], []
    for _ in range(500):
        t0 = time.perf_counter()
        nonce, ct = crypto_utils.encrypt_record(dek, "AIU24102453", sample)
        enc_times.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        crypto_utils.decrypt_record(dek, "AIU24102453", nonce, ct)
        dec_times.append((time.perf_counter() - t0) * 1000)
    print(f"Payload size          : {len(sample)} bytes")
    print(f"Mean encrypt time     : {statistics.mean(enc_times):.4f} ms  (stdev {statistics.stdev(enc_times):.4f})")
    print(f"Mean decrypt time     : {statistics.mean(dec_times):.4f} ms  (stdev {statistics.stdev(dec_times):.4f})")
    overhead = len(base64.b64decode(row.enc_data)) - len(sample)
    print(f"AES-GCM overhead      : {overhead} bytes (12-byte nonce is stored separately; "
          f"16-byte auth tag is appended to ciphertext)")

    print()
    print("=" * 78)
    print("4. NEGATIVE TESTS: tamper detection and wrong-key rejection (live output)")
    print("=" * 78)
    nonce, ct = crypto_utils.encrypt_record(dek, "AIU24102453", sample)
    print("[Test 4a] Correct key, untouched ciphertext:")
    try:
        crypto_utils.decrypt_record(dek, "AIU24102453", nonce, ct)
        print("          -> Decryption succeeded (expected).")
    except crypto_utils.CryptoError as exc:
        print(f"          -> Unexpected failure: {exc}")

    print("[Test 4b] Ciphertext modified by flipping one bit:")
    raw = bytearray(base64.b64decode(ct))
    raw[5] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode()
    try:
        crypto_utils.decrypt_record(dek, "AIU24102453", nonce, tampered)
        print("          -> Decryption succeeded (NOT expected -- would be a bug).")
    except crypto_utils.CryptoError as exc:
        print(f"          -> Rejected as expected: {exc}")

    print("[Test 4c] Correct ciphertext, wrong DEK (simulated stolen-DB-only attacker):")
    wrong_dek = os.urandom(crypto_utils.DEK_SIZE)
    try:
        crypto_utils.decrypt_record(wrong_dek, "AIU24102453", nonce, ct)
        print("          -> Decryption succeeded (NOT expected -- would be a bug).")
    except crypto_utils.CryptoError as exc:
        print(f"          -> Rejected as expected: {exc}")

    print("[Test 4d] Wrong master password when unlocking the keystore:")
    try:
        crypto_utils.unlock_keystore("TotallyWrongPassword", keystore)
        print("          -> Unlock succeeded (NOT expected -- would be a bug).")
    except crypto_utils.CryptoError as exc:
        print(f"          -> Rejected as expected: {exc}")

    print()
    print("=" * 78)
    print("5. AUDIT LOG produced by the actions above")
    print("=" * 78)
    for r in db.recent_log(10):
        print(f"  {r['ts']}  user={r['username'] or '-':<12} action={r['action']:<14} "
              f"target={r['target'] or '-':<12} ok={bool(r['success'])}  {r['detail']}")

    db.close()
    os.remove(DB_PATH)


if __name__ == "__main__":
    main()
