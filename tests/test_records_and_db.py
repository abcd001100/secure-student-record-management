"""
Integration tests covering the database layer, the record service
(validation + encryption + storage), and role-based access control.
Each test uses a fresh temporary SQLite file so tests never interfere
with each other or with the real students.db used by the GUI.
Run with:  python -m unittest -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth, crypto_utils, records, validators
from app.auth import AuthError, Session
from app.database import Database, DuplicateStudentIdError


def make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)  # let sqlite3 create it fresh
    return Database(path), path


class DatabaseAndRecordTests(unittest.TestCase):
    def setUp(self):
        self.db, self.db_path = make_db()
        self.dek = crypto_utils.unlock_keystore(
            "UnitTestMaster1", crypto_utils.create_keystore("UnitTestMaster1")
        )
        self.admin = Session(username="admin1", role="admin")
        self.staff = Session(username="staff1", role="staff")

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def sample_input(self, student_id="AIU24102453"):
        return records.StudentInput(
            student_id=student_id,
            full_name="Abdulaziz Taju Mohammedyasin",
            program="BCS (Hons)",
            intake="Sem3 2025-2026",
            ic_passport_no="A12345678",
            phone="+60123456789",
            address="Alor Setar, Kedah, Malaysia",
            guardian_contact="+60129876543",
            remarks="No known medical conditions.",
        )

    def test_add_and_view_roundtrip(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        view = records.view_student(self.db, self.dek, self.admin, "AIU24102453")
        self.assertEqual(view.phone, "+60123456789")
        self.assertEqual(view.ic_passport_no, "A12345678")

    def test_duplicate_student_id_rejected(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        with self.assertRaises(DuplicateStudentIdError):
            records.add_student(self.db, self.dek, self.admin, self.sample_input())

    def test_invalid_student_id_format_rejected(self):
        bad = self.sample_input(student_id="not-an-id")
        with self.assertRaises(validators.ValidationError):
            records.add_student(self.db, self.dek, self.admin, bad)

    def test_invalid_phone_rejected(self):
        bad = self.sample_input()
        bad.phone = "abc"
        with self.assertRaises(validators.ValidationError):
            records.add_student(self.db, self.dek, self.admin, bad)

    def test_empty_required_field_rejected(self):
        bad = self.sample_input()
        bad.address = "   "
        with self.assertRaises(validators.ValidationError):
            records.add_student(self.db, self.dek, self.admin, bad)

    def test_update_changes_encrypted_data(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        updated = self.sample_input()
        updated.phone = "+60111111111"
        records.update_student(self.db, self.dek, self.admin, updated)
        view = records.view_student(self.db, self.dek, self.admin, "AIU24102453")
        self.assertEqual(view.phone, "+60111111111")

    def test_staff_cannot_delete_record(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        with self.assertRaises(AuthError):
            records.delete_student(self.db, self.staff, "AIU24102453")

    def test_admin_can_delete_record(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        records.delete_student(self.db, self.admin, "AIU24102453")
        self.assertIsNone(self.db.get_student("AIU24102453"))

    def test_audit_log_records_view_and_add(self):
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        records.view_student(self.db, self.dek, self.admin, "AIU24102453")
        actions = [row["action"] for row in self.db.recent_log()]
        self.assertIn("ADD_STUDENT", actions)
        self.assertIn("VIEW_STUDENT", actions)

    def test_wrong_dek_cannot_read_existing_record(self):
        """Simulates an attacker who has stolen the SQLite file but not
        the master password: a different DEK cannot decrypt the row."""
        records.add_student(self.db, self.dek, self.admin, self.sample_input())
        wrong_dek = crypto_utils.unlock_keystore(
            "AnotherMaster2", crypto_utils.create_keystore("AnotherMaster2")
        )
        with self.assertRaises(crypto_utils.CryptoError):
            records.view_student(self.db, wrong_dek, self.admin, "AIU24102453")


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.db, self.db_path = make_db()

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_login_with_correct_password_succeeds(self):
        auth.create_user(self.db, "alice", "GoodPass123", "staff")
        session = auth.login(self.db, "alice", "GoodPass123")
        self.assertEqual(session.role, "staff")

    def test_login_with_wrong_password_fails(self):
        auth.create_user(self.db, "alice", "GoodPass123", "staff")
        with self.assertRaises(AuthError):
            auth.login(self.db, "alice", "WrongPassword")

    def test_account_locks_after_five_failed_logins(self):
        auth.create_user(self.db, "bob", "GoodPass123", "staff")
        for _ in range(5):
            with self.assertRaises(AuthError):
                auth.login(self.db, "bob", "WrongPassword")
        with self.assertRaises(AuthError):
            auth.login(self.db, "bob", "GoodPass123")  # even the correct password is now locked out

    def test_admin_can_reactivate_locked_account(self):
        auth.create_user(self.db, "erin", "GoodPass123", "staff")
        for _ in range(5):
            with self.assertRaises(AuthError):
                auth.login(self.db, "erin", "WrongPassword")
        admin_session = Session(username="admin1", role="admin")
        auth.reactivate_user(self.db, admin_session, "erin")
        session = auth.login(self.db, "erin", "GoodPass123")
        self.assertEqual(session.role, "staff")

    def test_staff_cannot_reactivate_account(self):
        auth.create_user(self.db, "frank", "GoodPass123", "staff")
        for _ in range(5):
            with self.assertRaises(AuthError):
                auth.login(self.db, "frank", "WrongPassword")
        staff_session = Session(username="staff_other", role="staff")
        with self.assertRaises(AuthError):
            auth.reactivate_user(self.db, staff_session, "frank")
        # still locked: staff could not reactivate it
        with self.assertRaises(AuthError):
            auth.login(self.db, "frank", "GoodPass123")

    def test_duplicate_username_rejected(self):
        auth.create_user(self.db, "carol", "GoodPass123", "admin")
        with self.assertRaises(Exception):
            auth.create_user(self.db, "carol", "AnotherPass1", "staff")

    def test_weak_password_rejected_at_creation(self):
        with self.assertRaises(validators.ValidationError):
            auth.create_user(self.db, "dave", "weak", "staff")

    def test_username_with_surrounding_whitespace_can_log_in(self):
        """Regression test: create_user() must store the *validated*
        (trimmed) username, not the raw argument, or an account created
        with an accidental leading/trailing space becomes permanently
        unable to log in -- every login lookup strips its input first,
        so an un-trimmed stored username can never match again."""
        auth.create_user(self.db, "  erin2 ", "GoodPass123", "staff")
        stored = self.db.get_user("erin2")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.username, "erin2")
        session = auth.login(self.db, "erin2", "GoodPass123")
        self.assertEqual(session.username, "erin2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
