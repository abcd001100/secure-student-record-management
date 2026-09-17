"""
records.py
----------
The record service is the only place in the application that is
allowed to combine plaintext student data with the DEK. It:

  1. validates every field,
  2. serialises the sensitive fields to a small JSON document,
  3. encrypts that document with AES-256-GCM (crypto_utils.encrypt_record),
     using the student ID as Associated Data so the ciphertext cannot
     be moved to a different record,
  4. stores the plaintext "index" columns (student ID, name, program,
     intake) and the ciphertext in SQLite,
  5. and enforces role-based access control for update/delete.

Reading a record back only decrypts the JSON document; the caller
(the GUI) decides whether to show the sensitive fields on screen or
only the non-sensitive summary, and every decryption is written to the
audit log so there is a record of who viewed what and when.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from . import crypto_utils, validators
from .auth import AuthError, Session
from .database import Database, DuplicateStudentIdError, StudentRow

SENSITIVE_FIELDS = ("ic_passport_no", "phone", "address", "guardian_contact", "remarks")


@dataclass
class StudentInput:
    student_id: str
    full_name: str
    program: str
    intake: str
    ic_passport_no: str
    phone: str
    address: str
    guardian_contact: str
    remarks: str = ""


@dataclass
class StudentView:
    student_id: str
    full_name: str
    program: str
    intake: str
    created_by: str
    created_at: str
    updated_at: Optional[str]
    ic_passport_no: str
    phone: str
    address: str
    guardian_contact: str
    remarks: str


def _validate_input(data: StudentInput) -> StudentInput:
    return StudentInput(
        student_id=validators.validate_student_id(data.student_id),
        full_name=validators.validate_name(data.full_name),
        program=validators.validate_program(data.program),
        intake=data.intake.strip(),
        ic_passport_no=validators.require_non_empty(data.ic_passport_no, "IC/Passport number"),
        phone=validators.validate_phone(data.phone),
        address=validators.require_non_empty(data.address, "Address"),
        guardian_contact=validators.require_non_empty(data.guardian_contact, "Guardian contact"),
        remarks=(data.remarks or "").strip(),
    )


def add_student(db: Database, dek: bytes, session: Session, data: StudentInput) -> None:
    clean = _validate_input(data)
    payload = {f: getattr(clean, f) for f in SENSITIVE_FIELDS}
    nonce_b64, ct_b64 = crypto_utils.encrypt_record(
        dek, clean.student_id, json.dumps(payload).encode("utf-8")
    )
    try:
        db.add_student(
            clean.student_id, clean.full_name, clean.program, clean.intake,
            nonce_b64, ct_b64, session.username,
        )
    except DuplicateStudentIdError:
        db.log(session.username, "ADD_STUDENT", clean.student_id, "duplicate", success=False)
        raise
    db.log(session.username, "ADD_STUDENT", clean.student_id, "created", success=True)


def update_student(db: Database, dek: bytes, session: Session, data: StudentInput) -> None:
    clean = _validate_input(data)
    existing = db.get_student(clean.student_id)
    if existing is None:
        raise ValueError(f"Student {clean.student_id} does not exist.")
    payload = {f: getattr(clean, f) for f in SENSITIVE_FIELDS}
    nonce_b64, ct_b64 = crypto_utils.encrypt_record(
        dek, clean.student_id, json.dumps(payload).encode("utf-8")
    )
    db.update_student(clean.student_id, clean.full_name, clean.program, clean.intake, nonce_b64, ct_b64)
    db.log(session.username, "UPDATE_STUDENT", clean.student_id, "updated", success=True)


def delete_student(db: Database, session: Session, student_id: str) -> None:
    if not session.is_admin:
        db.log(session.username, "DELETE_STUDENT", student_id, "denied: not admin", success=False)
        raise AuthError("Only an administrator may delete a student record.")
    db.delete_student(student_id)
    db.log(session.username, "DELETE_STUDENT", student_id, "deleted", success=True)


def view_student(db: Database, dek: bytes, session: Session, student_id: str) -> StudentView:
    row: Optional[StudentRow] = db.get_student(student_id)
    if row is None:
        raise ValueError(f"Student {student_id} not found.")
    try:
        plaintext = crypto_utils.decrypt_record(dek, row.student_id, row.enc_nonce, row.enc_data)
    except crypto_utils.CryptoError:
        db.log(session.username, "VIEW_STUDENT", student_id, "decryption failed", success=False)
        raise
    payload = json.loads(plaintext.decode("utf-8"))
    db.log(session.username, "VIEW_STUDENT", student_id, "sensitive fields decrypted", success=True)
    return StudentView(
        student_id=row.student_id, full_name=row.full_name, program=row.program,
        intake=row.intake or "", created_by=row.created_by, created_at=row.created_at,
        updated_at=row.updated_at, **{f: payload.get(f, "") for f in SENSITIVE_FIELDS},
    )


def list_students(db: Database) -> list[StudentRow]:
    """Non-sensitive summary list -- no decryption needed, so this can
    be shown on the dashboard without touching the DEK at all."""
    return db.list_students()
