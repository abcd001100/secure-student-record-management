"""
auth.py
-------
Authentication and role-based access control (RBAC).

Login is deliberately separate from the master-password / DEK-unlock
step in crypto_utils.py: unlocking the keystore proves the *application
instance* is allowed to decrypt data, while logging in proves *which
user* is operating it and what that user's role permits. A staff
account can therefore use the system without ever knowing the master
password, and every action they take is still attributed to their own
username in the audit log.

A simple brute-force mitigation is included: after 5 consecutive failed
logins an account is locked until an administrator reactivates it.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crypto_utils
from .database import Database, UserRecord

MAX_FAILED_LOGINS = 5


class AuthError(Exception):
    pass


@dataclass
class Session:
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def login(db: Database, username: str, password: str) -> Session:
    user: UserRecord | None = db.get_user(username)
    if user is None:
        db.log(username, "LOGIN", detail="unknown username", success=False)
        raise AuthError("Invalid username or password.")

    if not user.is_active:
        db.log(username, "LOGIN", detail="account locked/disabled", success=False)
        raise AuthError("This account is locked. Contact an administrator.")

    ok = crypto_utils.verify_password(password, user.pwd_salt, user.pwd_hash, user.pwd_iterations)
    if not ok:
        db.record_failed_login(username)
        refreshed = db.get_user(username)
        if refreshed and refreshed.failed_logins >= MAX_FAILED_LOGINS:
            db.set_user_active(username, False)
            db.log(username, "LOGIN", detail="locked after repeated failures", success=False)
            raise AuthError("Too many failed attempts. Account has been locked.")
        db.log(username, "LOGIN", detail="wrong password", success=False)
        raise AuthError("Invalid username or password.")

    db.reset_failed_logins(username)
    db.log(username, "LOGIN", detail="success", success=True)
    return Session(username=user.username, role=user.role)


def require_admin(session: Session) -> None:
    if not session.is_admin:
        raise AuthError("This action requires an administrator account.")


def create_user(db: Database, username: str, password: str, role: str) -> None:
    from . import validators
    validators.validate_username(username)
    validators.validate_password_strength(password)
    if role not in ("admin", "staff"):
        raise ValueError("role must be 'admin' or 'staff'")
    ph = crypto_utils.hash_password(password)
    db.create_user(username, role, ph.salt_b64, ph.hash_b64, ph.iterations)


def reactivate_user(db: Database, session: Session, username: str) -> None:
    """Re-enable a locked/disabled account and reset its failed-login
    counter. Restricted to administrators; this is the completion of
    the account-lockout workflow described in auth.login() above --
    without this function, a locked account has no path back to
    active except direct database access."""
    if not session.is_admin:
        db.log(session.username, "REACTIVATE_USER", username, "denied: not admin", success=False)
        raise AuthError("Only an administrator may reactivate an account.")
    target = db.get_user(username)
    if target is None:
        raise ValueError(f"User '{username}' does not exist.")
    db.set_user_active(username, True)
    db.reset_failed_logins(username)
    db.log(session.username, "REACTIVATE_USER", username, "reactivated", success=True)
