from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple

from auth.hashing import verify_password
from auth.totp import verify_code_with_replay_prevention

# Centralized brute-force lockout configuration
MAX_FAILED_ATTEMPTS: int = 5
LOCKOUT_DURATION_SECONDS: int = 60
INACTIVITY_TIMEOUT_SECONDS: int = 300  # 5 minutes


class CentralizedRateLimiter:
    """Thread-safe rate limiter tracking failed attempts and lockouts across all auth gates."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # {username: {"attempts": int, "locked_until": float}}
        self._records: Dict[str, dict] = {}
        # {username: last_verified_timestep}
        self._last_totp_timesteps: Dict[str, int] = {}

    def is_locked_out(self, username: str) -> Tuple[bool, int]:
        """Check if user is currently locked out. Returns (is_locked, seconds_remaining)."""
        normalized = username.strip().lower()
        now = time.time()
        with self._lock:
            record = self._records.get(normalized)
            if not record:
                return False, 0

            locked_until = record.get("locked_until", 0.0)
            if now < locked_until:
                return True, int(locked_until - now) + 1

            # Lockout expired
            if locked_until > 0.0 and now >= locked_until:
                self._records.pop(normalized, None)

            return False, 0

    def record_failed_attempt(self, username: str) -> Tuple[int, bool]:
        """
        Record a failed attempt (password or OTP).
        Returns (current_attempt_count, newly_locked_out).
        """
        normalized = username.strip().lower()
        now = time.time()
        with self._lock:
            record = self._records.setdefault(
                normalized, {"attempts": 0, "locked_until": 0.0})
            record["attempts"] += 1

            if record["attempts"] >= MAX_FAILED_ATTEMPTS:
                record["locked_until"] = now + LOCKOUT_DURATION_SECONDS
                return record["attempts"], True

            return record["attempts"], False

    def reset_failed_attempts(self, username: str) -> None:
        """Clear failed attempts on successful full authentication."""
        normalized = username.strip().lower()
        with self._lock:
            self._records.pop(normalized, None)

    def verify_totp_with_replay_check(self, username: str, secret: str, otp_code: str) -> bool:
        """Verify TOTP code and prevent replaying the same code within its time window."""
        normalized = username.strip().lower()
        with self._lock:
            last_step = self._last_totp_timesteps.get(normalized, 0)
            valid, new_step = verify_code_with_replay_prevention(
                secret, otp_code, last_step)
            if valid:
                self._last_totp_timesteps[normalized] = new_step
                return True
            return False


# Global singleton instance
rate_limiter = CentralizedRateLimiter()


def is_locked_out(username: str) -> Tuple[bool, int]:
    return rate_limiter.is_locked_out(username)


def record_failed_attempt(username: str) -> Tuple[int, bool]:
    return rate_limiter.record_failed_attempt(username)


def reset_failed_attempts(username: str) -> None:
    rate_limiter.reset_failed_attempts(username)


def verify_master_password(user: dict, password: str) -> bool:
    """Verify master password against stored bcrypt hash."""
    if not user or not password:
        return False
    hash_val = user.get("password_hash", "")
    return verify_password(password, hash_val)


def verify_totp(user: dict, otp_code: str) -> bool:
    """Verify 6-digit TOTP code with replay defense."""
    if not user or not otp_code:
        return False
    username = user.get("username", "")
    secret = user.get("totp_secret", "")
    return rate_limiter.verify_totp_with_replay_check(username, secret, otp_code)


def authenticate(user: dict, password: str, otp_code: str) -> bool:
    """Authenticate both factors (master password + TOTP code)."""
    return verify_master_password(user, password) and verify_totp(user, otp_code)


def cleanup_session_state(session_state) -> None:
    """
    Centralized sensitive-state purge.
    Purges all credentials, derived keys, secrets, decoded imports, and widget input buffers.
    """
    sensitive_keys = [
        # Authentication & credentials
        "authenticated",
        "user",
        "username",
        "password",
        "vault_key",
        "login_stage",
        "pending_user",
        "pending_username",
        "pending_password",
        "new_registration",
        "verified_incoming",
        "reauth_verified",
        "reauth_timestamp",
        # Stego & files
        "last_stego_png",
        "custom_cover_bytes",
        "recipient_key_val",
        "sender_key_val",
        # Widget inputs (Streamlit state persistence)
        "login_user_input",
        "login_pass_input",
        "login_otp_input",
        "reg_user",
        "reg_pass",
        "reg_confirm",
        "new_cred_site",
        "new_cred_user",
        "new_cred_pass_input",
        "new_cred_notes",
        "new_cred_pwd",
        "gen_pwd_val",
        "input_recipient_key",
        "input_sender_key",
        "reauth_pass_input",
    ]

    for key in sensitive_keys:
        if key in session_state:
            del session_state[key]

    # Clean up dynamically created widget keys (e.g. edit_pwd_*, toggle_*, del_*)
    keys_to_delete = [
        k for k in list(session_state.keys())
        if k.startswith(("edit_", "del_", "toggle_", "editing_"))
    ]
    for k in keys_to_delete:
        del session_state[k]

    session_state["authenticated"] = False
    session_state["username"] = ""


def check_inactivity_timeout(session_state) -> bool:
    """
    Check if active session has exceeded inactivity timeout.
    If timed out, purges session state and flags timeout.
    Returns True if timed out, False otherwise.
    """
    if not session_state.get("authenticated", False):
        return False

    now = time.time()
    last_active = session_state.get("last_activity_time", now)

    if now - last_active > INACTIVITY_TIMEOUT_SECONDS:
        cleanup_session_state(session_state)
        session_state["session_timed_out"] = True
        return True

    session_state["last_activity_time"] = now
    return False
