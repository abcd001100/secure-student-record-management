"""
Automated tests for app.crypto_utils: password hashing and AES-256-GCM
envelope encryption. Run with:  python -m unittest -v
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto_utils


class PasswordHashingTests(unittest.TestCase):
    def test_correct_password_verifies(self):
        ph = crypto_utils.hash_password("Correcthorse1")
        self.assertTrue(
            crypto_utils.verify_password("Correcthorse1", ph.salt_b64, ph.hash_b64, ph.iterations)
        )

    def test_wrong_password_is_rejected(self):
        ph = crypto_utils.hash_password("Correcthorse1")
        self.assertFalse(
            crypto_utils.verify_password("wrongpassword", ph.salt_b64, ph.hash_b64, ph.iterations)
        )

    def test_two_hashes_of_same_password_differ(self):
        """Random per-call salt means identical passwords never produce
        identical stored hashes (defends against rainbow-table lookups)."""
        ph1 = crypto_utils.hash_password("SamePassword1")
        ph2 = crypto_utils.hash_password("SamePassword1")
        self.assertNotEqual(ph1.salt_b64, ph2.salt_b64)
        self.assertNotEqual(ph1.hash_b64, ph2.hash_b64)


class KeystoreEnvelopeTests(unittest.TestCase):
    def test_correct_master_password_unwraps_dek(self):
        keystore = crypto_utils.create_keystore("MasterPass123")
        dek = crypto_utils.unlock_keystore("MasterPass123", keystore)
        self.assertEqual(len(dek), crypto_utils.DEK_SIZE)

    def test_wrong_master_password_is_rejected(self):
        keystore = crypto_utils.create_keystore("MasterPass123")
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.unlock_keystore("WrongPassword", keystore)

    def test_change_master_password_preserves_dek(self):
        keystore = crypto_utils.create_keystore("OldPass123")
        original_dek = crypto_utils.unlock_keystore("OldPass123", keystore)
        new_keystore = crypto_utils.change_master_password("OldPass123", "NewPass456", keystore)
        rotated_dek = crypto_utils.unlock_keystore("NewPass456", new_keystore)
        self.assertEqual(original_dek, rotated_dek)
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.unlock_keystore("OldPass123", new_keystore)

    def test_corrupted_keystore_wrapped_dek_is_rejected(self):
        """A keystore whose wrapped_dek field has been altered on disk
        (e.g. by a copy error or deliberate tampering) must fail to
        unwrap even with the correct master password, rather than
        silently returning wrong key material."""
        keystore = crypto_utils.create_keystore("MasterPass123")
        raw = bytearray(crypto_utils.base64.b64decode(keystore["wrapped_dek"]))
        raw[0] ^= 0xFF
        keystore["wrapped_dek"] = crypto_utils.base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.unlock_keystore("MasterPass123", keystore)


class RecordEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.dek = os.urandom(crypto_utils.DEK_SIZE)

    def test_roundtrip_ascii(self):
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", b'{"phone":"0123456789"}')
        pt = crypto_utils.decrypt_record(self.dek, "AIU24102453", nonce, ct)
        self.assertEqual(pt, b'{"phone":"0123456789"}')

    def test_roundtrip_unicode(self):
        text = '{"remarks":"student is called الطالب – café"}'.encode("utf-8")
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", text)
        pt = crypto_utils.decrypt_record(self.dek, "AIU24102453", nonce, ct)
        self.assertEqual(pt, text)

    def test_roundtrip_empty_payload(self):
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", b"")
        pt = crypto_utils.decrypt_record(self.dek, "AIU24102453", nonce, ct)
        self.assertEqual(pt, b"")

    def test_tampered_ciphertext_is_rejected(self):
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", b'{"phone":"0123456789"}')
        raw = bytearray(crypto_utils.base64.b64decode(ct))
        raw[0] ^= 0xFF  # flip bits in the first byte of the ciphertext
        tampered_ct = crypto_utils.base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.decrypt_record(self.dek, "AIU24102453", nonce, tampered_ct)

    def test_wrong_key_is_rejected(self):
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", b'{"phone":"0123456789"}')
        wrong_dek = os.urandom(crypto_utils.DEK_SIZE)
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.decrypt_record(wrong_dek, "AIU24102453", nonce, ct)

    def test_malformed_base64_ciphertext_is_rejected(self):
        """Malformed (non-base64) ciphertext must raise CryptoError
        rather than an unhandled ValueError/binascii.Error reaching the
        caller."""
        dek = os.urandom(crypto_utils.DEK_SIZE)
        nonce, _ = crypto_utils.encrypt_record(dek, "AIU24102453", b"data")
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.decrypt_record(dek, "AIU24102453", nonce, "not-valid-base64!!!")

    def test_ciphertext_bound_to_record_id(self):
        """A ciphertext encrypted for one student ID must be rejected if
        someone tries to decrypt it while claiming a different student ID
        (defends against copying an encrypted row into another record)."""
        nonce, ct = crypto_utils.encrypt_record(self.dek, "AIU24102453", b'{"phone":"0123456789"}')
        with self.assertRaises(crypto_utils.CryptoError):
            crypto_utils.decrypt_record(self.dek, "AIU24102999", nonce, ct)


if __name__ == "__main__":
    unittest.main(verbosity=2)
