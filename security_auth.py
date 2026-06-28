from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import pbkdf2_hmac, sha256
from pathlib import Path
from typing import Any

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError
except Exception:  # pragma: no cover - runtime dependency fallback
    PasswordHasher = None
    VerifyMismatchError = Exception
    VerificationError = Exception


ROOT_DIR = Path(__file__).resolve().parent
SECURITY_DIR = ROOT_DIR / "security"
AUTH_DB_PATH = Path(os.getenv("DIFD_AUTH_DB", str(SECURITY_DIR / "auth.db")))
INSTALL_STATE_PATH = Path(os.getenv("DIFD_INSTALL_STATE", str(AUTH_DB_PATH.parent / "install_state.json")))
SECURITY_EVENTS_PATH = Path(os.getenv("DIFD_SECURITY_EVENTS", str(AUTH_DB_PATH.parent / "security_events.jsonl")))
AUTH_BACKUP_DIR = Path(os.getenv("DIFD_AUTH_BACKUP_DIR", str(AUTH_DB_PATH.parent / "backups")))

VALID_ROLES = {"admin", "analyst"}
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
MIN_PASSWORD_LENGTH = int(os.getenv("DIFD_MIN_PASSWORD_LENGTH", "15"))
MAX_PASSWORD_LENGTH = int(os.getenv("DIFD_MAX_PASSWORD_LENGTH", "128"))
LOCKOUT_THRESHOLD = int(os.getenv("DIFD_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_SECONDS = int(os.getenv("DIFD_LOCKOUT_SECONDS", str(15 * 60)))
SESSION_TIMEOUT_SECONDS = int(os.getenv("DIFD_SESSION_TIMEOUT_SECONDS", str(60 * 60)))
PBKDF2_ITERATIONS = int(os.getenv("DIFD_PBKDF2_ITERATIONS", "310000"))
AUTH_METADATA_INSTALL_ID = "install_id"

COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "admin123",
    "qwerty123",
    "letmein123",
    "welcome123",
    "123456789012",
    "123456789012345",
    "passwordpassword",
    "adminadminadmin",
    "qwertyqwerty123",
}

if PasswordHasher is not None:
    ARGON2 = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
else:
    ARGON2 = None


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    role: str


class AuthError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_username(username: str) -> str:
    return username.strip().lower()


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    return str(value)


def log_security_event(
    event_type: str,
    *,
    username: str | None = None,
    success: bool = True,
    message: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    SECURITY_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": utc_now(),
        "event_type": event_type,
        "success": bool(success),
        "username": normalize_username(username) if username else None,
        "message": message[:1000],
        "details": details or {},
    }
    with SECURITY_EVENTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, default=_json_default, sort_keys=True) + "\n")


def recent_security_events(limit: int = 25) -> list[dict[str, Any]]:
    if not SECURITY_EVENTS_PATH.exists():
        return []
    bounded_limit = max(1, min(int(limit), 100))
    try:
        lines = SECURITY_EVENTS_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in reversed(lines[-bounded_limit:]):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append(
                {
                    "timestamp": "",
                    "event_type": "security_event_parse_failure",
                    "success": False,
                    "username": None,
                    "message": "A security event log line could not be parsed.",
                    "details": {},
                }
            )
    return events


def _file_hash_metadata(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {"exists": False}
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "exists": True,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def _code_hash_metadata() -> dict[str, dict[str, Any]]:
    tracked_files = ("app.py", "security_auth.py", "bootstrap_admin.py")
    return {name: _file_hash_metadata(ROOT_DIR / name) for name in tracked_files}


def _write_install_state(payload: dict[str, Any]) -> None:
    INSTALL_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = INSTALL_STATE_PATH.with_suffix(INSTALL_STATE_PATH.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(INSTALL_STATE_PATH)


def read_install_state() -> dict[str, Any] | None:
    if not INSTALL_STATE_PATH.exists():
        return None
    try:
        return json.loads(INSTALL_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "version": 0,
            "created_at": "",
            "created_by": "unknown",
            "reason": "unreadable_install_state",
            "auth_db_path": str(AUTH_DB_PATH),
            "error": "Install state file is present but could not be read.",
        }


def is_install_sealed() -> bool:
    return INSTALL_STATE_PATH.exists()


def ensure_db_install_id() -> str:
    with _managed_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        row = conn.execute(
            "SELECT value FROM auth_metadata WHERE key = ?",
            (AUTH_METADATA_INSTALL_ID,),
        ).fetchone()
        if row is not None:
            return str(row["value"])
        install_id = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO auth_metadata (key, value, updated_at) VALUES (?, ?, ?)",
            (AUTH_METADATA_INSTALL_ID, install_id, utc_now()),
        )
        return install_id


def seal_installation(*, created_by: str, reason: str) -> dict[str, Any]:
    db_install_id = ensure_db_install_id() if AUTH_DB_PATH.exists() else None
    existing = read_install_state()
    if existing is not None:
        if db_install_id and not existing.get("db_install_id"):
            existing["db_install_id"] = db_install_id
            existing["updated_at"] = utc_now()
            existing["update_reason"] = "added_db_install_id"
            _write_install_state(existing)
            log_security_event(
                "install_seal_updated",
                username=created_by,
                success=True,
                message="Installation seal updated with auth DB install ID.",
                details={"install_state_path": str(INSTALL_STATE_PATH), "auth_db_path": str(AUTH_DB_PATH)},
            )
        return existing

    payload = {
        "version": 1,
        "created_at": utc_now(),
        "created_by": normalize_username(created_by),
        "reason": reason,
        "auth_db_path": str(AUTH_DB_PATH),
        "db_install_id": db_install_id,
        "app_root": str(ROOT_DIR),
        "code_hashes": _code_hash_metadata(),
    }
    _write_install_state(payload)
    log_security_event(
        "install_sealed",
        username=created_by,
        success=True,
        message=f"Installation sealed after {reason}.",
        details={"install_state_path": str(INSTALL_STATE_PATH), "auth_db_path": str(AUTH_DB_PATH)},
    )
    return payload


def _count_users_without_init() -> tuple[int | None, str, str | None]:
    if not AUTH_DB_PATH.exists():
        return 0, "missing", None
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(AUTH_DB_PATH, timeout=30)
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        if row is None:
            return 0, "missing_users_table", None
        count_row = connection.execute("SELECT COUNT(*) FROM users").fetchone()
        metadata_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'auth_metadata'"
        ).fetchone()
        db_install_id = None
        if metadata_table is not None:
            metadata_row = connection.execute(
                "SELECT value FROM auth_metadata WHERE key = ?",
                (AUTH_METADATA_INSTALL_ID,),
            ).fetchone()
            if metadata_row is not None:
                db_install_id = str(metadata_row["value"])
        return int(count_row[0]), "ok", db_install_id
    except sqlite3.Error:
        return None, "unreadable", None
    finally:
        if connection is not None:
            connection.close()


def get_auth_store_status() -> dict[str, Any]:
    sealed = is_install_sealed()
    install_state = read_install_state()
    user_total, db_status, db_install_id = _count_users_without_init()
    sealed_install_id = install_state.get("db_install_id") if install_state else None

    base_status: dict[str, Any] = {
        "auth_db_path": str(AUTH_DB_PATH),
        "auth_db_exists": AUTH_DB_PATH.exists(),
        "install_state_path": str(INSTALL_STATE_PATH),
        "install_sealed": sealed,
        "install_state": install_state,
        "security_events_path": str(SECURITY_EVENTS_PATH),
        "backup_dir": str(AUTH_BACKUP_DIR),
        "user_count": user_total,
        "db_status": db_status,
        "db_install_id": db_install_id,
        "sealed_db_install_id": sealed_install_id,
        "needs_seal": False,
    }

    if user_total is None:
        return {
            **base_status,
            "state": "recovery_required",
            "message": "The authentication database is unreadable. Restore a trusted backup before continuing.",
        }

    if sealed and (db_status != "ok" or user_total <= 0):
        return {
            **base_status,
            "state": "recovery_required",
            "message": "The authentication database is missing or empty after setup was sealed.",
        }

    if sealed and sealed_install_id and db_install_id != sealed_install_id:
        return {
            **base_status,
            "state": "recovery_required",
            "message": "The authentication database does not match the sealed installation identity.",
        }

    if user_total <= 0:
        return {
            **base_status,
            "state": "not_initialized",
            "message": "No user accounts exist. First-admin bootstrap is required.",
        }

    return {
        **base_status,
        "state": "ready",
        "needs_seal": (not sealed) or (sealed and not sealed_install_id),
        "message": "Authentication database is ready.",
    }


def _require_ready_auth_store(*, actor: str | None, action: str) -> None:
    status = get_auth_store_status()
    if status["state"] != "ready":
        log_security_event(
            f"{action}_refused",
            username=actor,
            success=False,
            message=f"{action} refused because the auth store is not ready.",
            details=status,
        )
        raise AuthError("Authentication storage is not ready. Restore the auth database before making account changes.")


def create_auth_db_backup(reason: str, *, actor: str | None = None) -> Path | None:
    if not AUTH_DB_PATH.exists():
        log_security_event(
            "auth_db_backup_skipped",
            username=actor,
            success=False,
            message="Auth DB backup skipped because the database file does not exist.",
            details={"reason": reason, "auth_db_path": str(AUTH_DB_PATH)},
        )
        return None

    AUTH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_reason = re.sub(r"[^a-zA-Z0-9_.-]+", "-", reason.strip().lower()).strip("-") or "auth-change"
    backup_path = AUTH_BACKUP_DIR / f"auth-{stamp}-{safe_reason}-{secrets.token_hex(3)}.db"
    shutil.copy2(AUTH_DB_PATH, backup_path)
    log_security_event(
        "auth_db_backup_created",
        username=actor,
        success=True,
        message=f"Auth DB backup created before {reason}.",
        details={"backup_path": str(backup_path), "auth_db_path": str(AUTH_DB_PATH), "reason": reason},
    )
    return backup_path


def latest_auth_db_backup() -> Path | None:
    if not AUTH_BACKUP_DIR.exists():
        return None
    backups = sorted(AUTH_BACKUP_DIR.glob("auth-*.db"), key=lambda item: item.stat().st_mtime, reverse=True)
    return backups[0] if backups else None


def _connect() -> sqlite3.Connection:
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(AUTH_DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _managed_connect() -> Any:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    with _managed_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_scheme TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
                is_active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                event_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                session_id TEXT,
                message TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS browser_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                session_id TEXT,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_events(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_browser_sessions_token ON browser_sessions(token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_browser_sessions_username ON browser_sessions(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_browser_sessions_expires ON browser_sessions(expires_at)")


def user_count() -> int:
    init_db()
    with _managed_connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
    return int(row["count"])


def validate_username(username: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_RE.fullmatch(normalized):
        raise AuthError("Username must be 3-64 characters and use only letters, numbers, dots, underscores, or hyphens.")
    return normalized


def validate_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password or "") > MAX_PASSWORD_LENGTH:
        raise AuthError(f"Password must be no more than {MAX_PASSWORD_LENGTH} characters.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        raise AuthError("Password is too common.")
    if password.strip() != password:
        raise AuthError("Password cannot begin or end with whitespace.")


def _hash_password(password: str) -> tuple[str, str]:
    if ARGON2 is not None:
        return ARGON2.hash(password), "argon2id"

    salt = secrets.token_bytes(16)
    digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    encoded = f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"
    return encoded, "pbkdf2_sha256"


def _hash_browser_session_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _verify_password(password: str, stored_hash: str, scheme: str) -> tuple[bool, bool]:
    if scheme == "argon2id":
        if ARGON2 is None:
            raise AuthError("Argon2 password support is unavailable. Install argon2-cffi in the main app environment.")
        try:
            valid = ARGON2.verify(stored_hash, password)
        except VerifyMismatchError:
            return False, False
        except VerificationError:
            return False, False
        return bool(valid), bool(ARGON2.check_needs_rehash(stored_hash))

    if scheme == "pbkdf2_sha256":
        try:
            _, iterations_text, salt_hex, digest_hex = stored_hash.split("$", 3)
            iterations = int(iterations_text)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
        except (ValueError, TypeError):
            log_security_event(
                "password_hash_parse_failure",
                success=False,
                message="Stored password hash could not be parsed.",
                details={"scheme": scheme},
            )
            return False, False
        actual = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        needs_rehash = ARGON2 is not None or iterations < PBKDF2_ITERATIONS
        return hmac.compare_digest(actual, expected), needs_rehash

    return False, False


def _insert_audit_event(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    username: str | None = None,
    success: bool = True,
    session_id: str | None = None,
    message: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO audit_events (timestamp, username, event_type, success, session_id, message)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (utc_now(), normalize_username(username) if username else None, event_type, int(success), session_id, message[:500]),
    )


def log_event(
    event_type: str,
    *,
    username: str | None = None,
    success: bool = True,
    session_id: str | None = None,
    message: str = "",
) -> None:
    init_db()
    with _managed_connect() as conn:
        _insert_audit_event(
            conn,
            event_type,
            username=username,
            success=success,
            session_id=session_id,
            message=message,
        )


def create_user(username: str, password: str, role: str = "analyst", *, created_by: str = "bootstrap") -> None:
    status = get_auth_store_status()
    if status["state"] == "recovery_required":
        log_security_event(
            "user_create_refused",
            username=created_by,
            success=False,
            message="User creation refused because the auth store requires recovery.",
            details=status,
        )
        raise AuthError("Authentication storage requires recovery before user accounts can be changed.")
    if status["state"] == "not_initialized" and created_by != "bootstrap":
        raise AuthError("First admin bootstrap is required before additional users can be created.")

    init_db()
    existing_users = user_count()
    if created_by == "bootstrap" and is_install_sealed():
        log_security_event(
            "bootstrap_refused",
            username=created_by,
            success=False,
            message="Bootstrap user creation refused because installation is sealed.",
            details={"auth_db_path": str(AUTH_DB_PATH), "install_state_path": str(INSTALL_STATE_PATH)},
        )
        raise AuthError("This installation is already sealed. Restore the auth database instead of creating a new admin.")
    normalized = validate_username(username)
    selected_role = role.strip().lower()
    if selected_role not in VALID_ROLES:
        raise AuthError("Role must be admin or analyst.")
    validate_password(password)
    password_hash, scheme = _hash_password(password)
    now = utc_now()
    if existing_users > 0:
        create_auth_db_backup("create_user", actor=created_by)

    try:
        with _managed_connect() as conn:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, password_scheme, role, is_active, failed_attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, 0, ?, ?)
                """,
                (normalized, password_hash, scheme, selected_role, now, now),
            )
    except sqlite3.IntegrityError as exc:
        raise AuthError("A user with that username already exists.") from exc

    log_event("user_created", username=created_by, success=True, message=f"Created {selected_role} user '{normalized}'.")


def bootstrap_first_admin(username: str, password: str) -> None:
    status = get_auth_store_status()
    if status["state"] == "recovery_required":
        log_security_event(
            "bootstrap_refused",
            username="bootstrap",
            success=False,
            message="Bootstrap refused because the installation requires auth database recovery.",
            details=status,
        )
        raise AuthError("This installation requires auth database recovery. Restore a trusted backup instead.")
    if status["state"] == "ready":
        raise AuthError("At least one user already exists. Create additional users from the admin UI.")

    create_user(username, password, role="admin", created_by="bootstrap")
    normalized = normalize_username(username)
    seal_installation(created_by=normalized, reason="first_admin_created")


def authenticate_user(username: str, password: str, *, session_id: str | None = None) -> AuthenticatedUser | None:
    init_db()
    normalized = normalize_username(username)
    now_epoch = time.time()

    with _managed_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (normalized,)).fetchone()
        if row is None:
            _insert_audit_event(
                conn,
                "login_failure",
                username=normalized,
                success=False,
                session_id=session_id,
                message="Unknown username.",
            )
            return None

        if not int(row["is_active"]):
            _insert_audit_event(
                conn,
                "login_failure",
                username=normalized,
                success=False,
                session_id=session_id,
                message="Inactive account.",
            )
            return None

        locked_until = row["locked_until"]
        if locked_until is not None and float(locked_until) > now_epoch:
            _insert_audit_event(
                conn,
                "login_failure",
                username=normalized,
                success=False,
                session_id=session_id,
                message="Account locked.",
            )
            return None

        valid, needs_rehash = _verify_password(password, row["password_hash"], row["password_scheme"])
        if not valid:
            failed_attempts = int(row["failed_attempts"]) + 1
            lock_until = now_epoch + LOCKOUT_SECONDS if failed_attempts >= LOCKOUT_THRESHOLD else None
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (failed_attempts, lock_until, utc_now(), row["id"]),
            )
            message = "Account locked after repeated failed attempts." if lock_until else "Invalid password."
            _insert_audit_event(
                conn,
                "login_failure",
                username=normalized,
                success=False,
                session_id=session_id,
                message=message,
            )
            return None

        new_hash = row["password_hash"]
        new_scheme = row["password_scheme"]
        if needs_rehash:
            new_hash, new_scheme = _hash_password(password)

        now_text = utc_now()
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_scheme = ?, failed_attempts = 0, locked_until = NULL,
                last_login_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_hash, new_scheme, now_text, now_text, row["id"]),
        )

    log_event("login_success", username=normalized, success=True, session_id=session_id)
    return AuthenticatedUser(username=normalized, role=str(row["role"]))


def create_browser_session(username: str, *, session_id: str | None = None) -> str:
    init_db()
    normalized = validate_username(username)
    token = secrets.token_urlsafe(32)
    token_hash = _hash_browser_session_token(token)
    now_text = utc_now()
    expires_at = time.time() + SESSION_TIMEOUT_SECONDS

    with _managed_connect() as conn:
        row = conn.execute(
            "SELECT is_active FROM users WHERE username = ?",
            (normalized,),
        ).fetchone()
        if row is None or not int(row["is_active"]):
            raise AuthError("Cannot create a session for an inactive or missing user.")
        conn.execute(
            """
            INSERT INTO browser_sessions
                (token_hash, username, session_id, created_at, last_seen_at, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
            """,
            (token_hash, normalized, session_id, now_text, now_text, expires_at),
        )

    log_event(
        "browser_session_created",
        username=normalized,
        success=True,
        session_id=session_id,
        message="Persistent browser session created.",
    )
    return token


def restore_browser_session(token: str, *, session_id: str | None = None) -> dict[str, Any] | None:
    if not token:
        return None

    init_db()
    token_hash = _hash_browser_session_token(token)
    now_epoch = time.time()
    now_text = utc_now()
    next_expiry = now_epoch + SESSION_TIMEOUT_SECONDS

    with _managed_connect() as conn:
        row = conn.execute(
            """
            SELECT bs.username, bs.expires_at, bs.revoked_at, users.role, users.is_active
            FROM browser_sessions bs
            JOIN users ON users.username = bs.username
            WHERE bs.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if row["revoked_at"] is not None or not int(row["is_active"]):
            return None
        if float(row["expires_at"]) <= now_epoch:
            conn.execute(
                "UPDATE browser_sessions SET revoked_at = ? WHERE token_hash = ?",
                (now_text, token_hash),
            )
            return None
        conn.execute(
            """
            UPDATE browser_sessions
            SET last_seen_at = ?, expires_at = ?, session_id = COALESCE(?, session_id)
            WHERE token_hash = ?
            """,
            (now_text, next_expiry, session_id, token_hash),
        )

    return {
        "username": str(row["username"]),
        "role": str(row["role"]),
        "expires_at": next_expiry,
    }


def refresh_browser_session(token: str, *, session_id: str | None = None) -> bool:
    if not token:
        return False

    init_db()
    token_hash = _hash_browser_session_token(token)
    now_epoch = time.time()
    now_text = utc_now()
    next_expiry = now_epoch + SESSION_TIMEOUT_SECONDS

    with _managed_connect() as conn:
        cursor = conn.execute(
            """
            UPDATE browser_sessions
            SET last_seen_at = ?, expires_at = ?, session_id = COALESCE(?, session_id)
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND expires_at > ?
            """,
            (now_text, next_expiry, session_id, token_hash, now_epoch),
        )
        return cursor.rowcount > 0


def revoke_browser_session(
    token: str,
    *,
    username: str | None = None,
    session_id: str | None = None,
    reason: str = "logout",
) -> None:
    if not token:
        return

    init_db()
    token_hash = _hash_browser_session_token(token)
    now_text = utc_now()
    with _managed_connect() as conn:
        conn.execute(
            """
            UPDATE browser_sessions
            SET revoked_at = COALESCE(revoked_at, ?)
            WHERE token_hash = ?
            """,
            (now_text, token_hash),
        )
    log_event(
        "browser_session_revoked",
        username=username,
        success=True,
        session_id=session_id,
        message=f"Persistent browser session revoked: {reason}.",
    )


def list_users() -> list[dict[str, Any]]:
    init_db()
    with _managed_connect() as conn:
        rows = conn.execute(
            """
            SELECT username, role, is_active, failed_attempts, locked_until, created_at, last_login_at
            FROM users
            ORDER BY username
            """
        ).fetchall()
    return [dict(row) for row in rows]


def set_user_active(username: str, active: bool, *, changed_by: str) -> None:
    _require_ready_auth_store(actor=changed_by, action="set_user_active")
    init_db()
    normalized = validate_username(username)
    create_auth_db_backup("set_user_active", actor=changed_by)
    with _managed_connect() as conn:
        cursor = conn.execute(
            "UPDATE users SET is_active = ?, updated_at = ? WHERE username = ?",
            (int(active), utc_now(), normalized),
        )
        changed_rows = cursor.rowcount
    if changed_rows == 0:
        raise AuthError("User not found.")
    action = "enabled" if active else "disabled"
    log_event("user_status_changed", username=changed_by, success=True, message=f"{action.title()} user '{normalized}'.")


def update_password(username: str, password: str, *, changed_by: str) -> None:
    _require_ready_auth_store(actor=changed_by, action="update_password")
    init_db()
    normalized = validate_username(username)
    validate_password(password)
    password_hash, scheme = _hash_password(password)
    create_auth_db_backup("update_password", actor=changed_by)
    with _managed_connect() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_scheme = ?, failed_attempts = 0, locked_until = NULL, updated_at = ?
            WHERE username = ?
            """,
            (password_hash, scheme, utc_now(), normalized),
        )
        changed_rows = cursor.rowcount
    if changed_rows == 0:
        raise AuthError("User not found.")
    log_event("password_changed", username=changed_by, success=True, message=f"Password changed for '{normalized}'.")


def recent_audit_events(limit: int = 25) -> list[dict[str, Any]]:
    init_db()
    bounded_limit = max(1, min(int(limit), 100))
    with _managed_connect() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, username, event_type, success, session_id, message
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]
