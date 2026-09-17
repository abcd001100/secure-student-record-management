"""
validators.py
--------------
Input validation for every field that reaches the database or the
cryptographic layer. Validation is deliberately performed BEFORE
encryption: rejecting bad input early means the system never wastes a
key operation on data that would fail anyway, and it stops obviously
malformed data from ever being stored.
"""

from __future__ import annotations

import re

STUDENT_ID_RE = re.compile(r"^[A-Z]{2,5}\d{6,10}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


class ValidationError(Exception):
    pass


def require_non_empty(value: str, field_name: str) -> str:
    if value is None or not value.strip():
        raise ValidationError(f"{field_name} cannot be empty.")
    return value.strip()


def validate_student_id(value: str) -> str:
    value = require_non_empty(value, "Student ID").upper()
    if not STUDENT_ID_RE.match(value):
        raise ValidationError(
            "Student ID must look like AIU24102453 (2-5 letters followed by 6-10 digits)."
        )
    return value


def validate_name(value: str) -> str:
    value = require_non_empty(value, "Full name")
    if len(value) < 2 or len(value) > 100:
        raise ValidationError("Full name must be between 2 and 100 characters.")
    return value


def validate_program(value: str) -> str:
    return require_non_empty(value, "Program")


def validate_email(value: str) -> str:
    value = require_non_empty(value, "Email").lower()
    if not EMAIL_RE.match(value):
        raise ValidationError("Email address is not in a valid format.")
    return value


def validate_phone(value: str) -> str:
    value = require_non_empty(value, "Phone number")
    if not PHONE_RE.match(value):
        raise ValidationError("Phone number must contain 7-15 digits, optionally starting with +.")
    return value


def validate_username(value: str) -> str:
    value = require_non_empty(value, "Username")
    if not USERNAME_RE.match(value):
        raise ValidationError("Username must be 3-20 characters: letters, digits, or underscore.")
    return value


def validate_password_strength(value: str) -> str:
    if value is None or len(value) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not (any(c.isupper() for c in value) and any(c.isdigit() for c in value)):
        raise ValidationError("Password must contain at least one uppercase letter and one digit.")
    return value
