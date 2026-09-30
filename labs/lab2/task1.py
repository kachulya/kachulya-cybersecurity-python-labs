import os
import re
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import List, Set, Optional, Any

class User:
    def __init__(self, username: str, email: str, role: str = "user"):
        self.username = username
        self._email = None
        self.email = email
        self.role = role
        self.active = True
        self.__password_hash: Optional[bytes] = None
        self.__password_salt: Optional[bytes] = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        # Локальна частина: латинська літера, 3-64 символи (літери, цифри, . _ -), @, домен з крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Недійсний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, 100000
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, 100000
        )
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return f"User({self.username}, {self.email}, Role: {self.role}, Active: {self.active})"

class Admin(User):
    def __init__(self, username: str, email: str, permissions: Optional[Set[str]] = None):
        super().__init__(username, email, role="admin")
        self.permissions = permissions if permissions is not None else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self):
        return super().__str__() + f" Permissions: {list(self.permissions)}"

class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            return False
        return (datetime.now(timezone.utc) - self.last_activity) <= timedelta(seconds=timeout_sec)

@dataclass
class LogEntry:
    timestamp: datetime
    username: str
    action: str

class AuditLog:
    def __init__(self):
        self.logs: List[LogEntry] = []

    def add_log(self, username: str, action: str):
        self.logs.append(LogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self):
        for log in self.logs:
            print(f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] {log.username}: {log.action}")

class UserAccount:
    SESSION_TIMEOUT_SEC = 900

    def __init__(self, user: User, audit_log: Optional[AuditLog] = None):
        self.user = user
        self.session: Optional[Session] = None
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure (inactive)")
            return False
        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        self.audit_log.add_log(self.user.username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        if self.session and self.session.is_active(self.SESSION_TIMEOUT_SEC):
            self.session.touch()
            return True
        return False

    def logout(self):
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        raise KeyError(f"Invalid key '{key}'. Allowed: 'user', 'session', 'audit_log'")

    def __setitem__(self, key: str, value: Any):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Expected User instance")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Expected Session instance or None")
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Expected AuditLog instance")
            self.audit_log = value
        else:
            raise KeyError(f"Key '{key}' cannot be modified")