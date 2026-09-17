"""
database.py
------------
SQLite persistence layer for the Secure Student Record Management
system. All queries use parameterised placeholders ("?") so that user
input is always passed as bound data, never concatenated into SQL
text -- this is what prevents SQL injection in this application.

Three tables are used:

  users       Login accounts (admin / staff) with a PBKDF2 password
              hash -- never a plaintext password.
  students    One row per student. full_name / student_id / program /
              intake are stored in plaintext because they are needed
              for sorting, searching and display in the record list.
              enc_nonce / enc_data hold the AES-256-GCM-encrypted blob
              of the sensitive fields (IC/passport number, phone,
              address, guardian contact, and academic/medical remarks).
  audit_log   An append-only trail of security-relevant events (logins,
              record access, record changes) used for the security
              section of the report and for real accountability.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('admin', 'staff')),
    pwd_salt      TEXT NOT NULL,
    pwd_hash      TEXT NOT NULL,
    pwd_iterations INTEGER NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   TEXT UNIQUE NOT NULL,
    full_name    TEXT NOT NULL,
    program      TEXT NOT NULL,
    intake       TEXT,
    enc_nonce    TEXT NOT NULL,
    enc_data     TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    username TEXT,
    action   TEXT NOT NULL,
    target   TEXT,
    detail   TEXT,
    success  INTEGER NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DuplicateStudentIdError(Exception):
    pass


class DuplicateUsernameError(Exception):
    pass


@dataclass
class UserRecord:
    id: int
    username: str
    role: str
    pwd_salt: str
    pwd_hash: str
    pwd_iterations: int
    is_active: bool
    failed_logins: int


@dataclass
class StudentRow:
    id: int
    student_id: str
    full_name: str
    program: str
    intake: Optional[str]
    enc_nonce: str
    enc_data: str
    created_by: str
    created_at: str
    updated_at: Optional[str]


class Database:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        with self.conn:
            self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    # -- users -------------------------------------------------------
    def create_user(self, username: str, role: str, pwd_salt: str, pwd_hash: str, iterations: int) -> None:
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO users (username, role, pwd_salt, pwd_hash, pwd_iterations, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (username, role, pwd_salt, pwd_hash, iterations, _now()),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateUsernameError(f"Username '{username}' already exists.") from exc

    def get_user(self, username: str) -> Optional[UserRecord]:
        row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return None
        return UserRecord(
            id=row["id"], username=row["username"], role=row["role"],
            pwd_salt=row["pwd_salt"], pwd_hash=row["pwd_hash"],
            pwd_iterations=row["pwd_iterations"], is_active=bool(row["is_active"]),
            failed_logins=row["failed_logins"],
        )

    def list_users(self) -> list[UserRecord]:
        rows = self.conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [
            UserRecord(
                id=r["id"], username=r["username"], role=r["role"],
                pwd_salt=r["pwd_salt"], pwd_hash=r["pwd_hash"],
                pwd_iterations=r["pwd_iterations"], is_active=bool(r["is_active"]),
                failed_logins=r["failed_logins"],
            )
            for r in rows
        ]

    def record_failed_login(self, username: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE users SET failed_logins = failed_logins + 1 WHERE username = ?",
                (username,),
            )

    def reset_failed_logins(self, username: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE users SET failed_logins = 0 WHERE username = ?", (username,)
            )

    def set_user_active(self, username: str, is_active: bool) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE users SET is_active = ? WHERE username = ?", (int(is_active), username)
            )

    def user_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

    # -- students ------------------------------------------------------
    def add_student(self, student_id: str, full_name: str, program: str, intake: str,
                     enc_nonce: str, enc_data: str, created_by: str) -> None:
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO students (student_id, full_name, program, intake, enc_nonce, "
                    "enc_data, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (student_id, full_name, program, intake, enc_nonce, enc_data, created_by, _now()),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateStudentIdError(f"Student ID '{student_id}' already exists.") from exc

    def update_student(self, student_id: str, full_name: str, program: str, intake: str,
                        enc_nonce: str, enc_data: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE students SET full_name=?, program=?, intake=?, enc_nonce=?, enc_data=?, "
                "updated_at=? WHERE student_id=?",
                (full_name, program, intake, enc_nonce, enc_data, _now(), student_id),
            )

    def delete_student(self, student_id: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM students WHERE student_id = ?", (student_id,))

    def get_student(self, student_id: str) -> Optional[StudentRow]:
        row = self.conn.execute(
            "SELECT * FROM students WHERE student_id = ?", (student_id,)
        ).fetchone()
        if row is None:
            return None
        return StudentRow(**{k: row[k] for k in row.keys()})

    def list_students(self) -> list[StudentRow]:
        rows = self.conn.execute("SELECT * FROM students ORDER BY student_id").fetchall()
        return [StudentRow(**{k: r[k] for k in r.keys()}) for r in rows]

    # -- audit log -----------------------------------------------------
    def log(self, username: Optional[str], action: str, target: str = "", detail: str = "",
            success: bool = True) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit_log (ts, username, action, target, detail, success) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (_now(), username, action, target, detail, int(success)),
            )

    def recent_log(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
