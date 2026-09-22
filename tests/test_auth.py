from __future__ import annotations

import time
import unittest

from auth.hashing import hash_password, verify_password
from auth.session import (
    authenticate,
    check_inactivity_timeout,
    cleanup_session_state,
    is_locked_out,
    record_failed_attempt,
    reset_failed_attempts,
    verify_master_password,
    verify_totp,
)
from auth.totp import (
    generate_qr_code_image,
    generate_secret,
    get_current_code_for_testing,
    get_totp_uri,
    verify_code,
    verify_code_with_replay_prevention,
)


class TestAuthLayer(unittest.TestCase):
    def setUp(self) -> None:
        self.username = "test_alice"
        reset_failed_attempts(self.username)

    def tearDown(self) -> None:
        reset_failed_attempts(self.username)

    def test_bcrypt_hashing_and_verification(self) -> None:
        password = "SecurePassword2026!"
        pwd_hash = hash_password(password)

        self.assertTrue(pwd_hash.startswith("$2b$"))
        self.assertTrue(verify_password(password, pwd_hash))
        self.assertFalse(verify_password("WrongPassword!", pwd_hash))
        self.assertFalse(verify_password("", pwd_hash))

    def test_totp_workflow_and_qr_code(self) -> None:
        secret = generate_secret()
        self.assertEqual(len(secret), 32)

        current_code = get_current_code_for_testing(secret)
        self.assertEqual(len(current_code), 6)
        self.assertTrue(verify_code(secret, current_code))

        # Reject invalid codes
        self.assertFalse(verify_code(
            secret, "000000" if current_code != "000000" else "111111"))
        self.assertFalse(verify_code(secret, "abc123"))
        self.assertFalse(verify_code(secret, ""))

        # Test URI and QR generation
        uri = get_totp_uri(secret, "alice")
        self.assertTrue(uri.startswith("otpauth://totp/SentinelVault:alice"))
        qr_bytes = generate_qr_code_image(uri)
        self.assertTrue(qr_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_totp_replay_prevention(self) -> None:
        secret = generate_secret()
        code = get_current_code_for_testing(secret)

        # First verification succeeds
        valid1, step1 = verify_code_with_replay_prevention(
            secret, code, last_verified_timestep=0)
        self.assertTrue(valid1)
        self.assertGreater(step1, 0)

        # Second verification of the SAME code within the same time step MUST be rejected
        valid2, step2 = verify_code_with_replay_prevention(
            secret, code, last_verified_timestep=step1)
        self.assertFalse(valid2)
        self.assertEqual(step2, step1)

    def test_centralized_lockout_on_failed_attempts(self) -> None:
        locked, _ = is_locked_out(self.username)
        self.assertFalse(locked)

        # Record 4 failures
        for i in range(1, 5):
            attempts, newly_locked = record_failed_attempt(self.username)
            self.assertEqual(attempts, i)
            self.assertFalse(newly_locked)

        # 5th failure triggers lockout
        attempts, newly_locked = record_failed_attempt(self.username)
        self.assertEqual(attempts, 5)
        self.assertTrue(newly_locked)

        locked, remaining = is_locked_out(self.username)
        self.assertTrue(locked)
        self.assertGreater(remaining, 0)

        # Reset works
        reset_failed_attempts(self.username)
        locked, _ = is_locked_out(self.username)
        self.assertFalse(locked)

    def test_session_cleanup_purges_all_secrets(self) -> None:
        mock_state = {
            "authenticated": True,
            "username": "alice",
            "password": "MasterPassword123!",
            "vault_key": b"\x01" * 32,
            "pending_password": "PlaintextPassword!",
            "new_registration": {"secret": "JBSWY3DPEHPK3PXP"},
            "verified_incoming": [{"password": "leaked"}],
            "login_pass_input": "PassWidgetVal",
            "reg_pass": "RegWidgetVal",
            "new_cred_pass_input": "CredWidgetVal",
            "edit_pwd_123": "EditWidgetVal",
            "custom_cover_bytes": b"fake_png",
        }

        cleanup_session_state(mock_state)

        self.assertFalse(mock_state["authenticated"])
        self.assertEqual(mock_state["username"], "")
        self.assertNotIn("password", mock_state)
        self.assertNotIn("vault_key", mock_state)
        self.assertNotIn("pending_password", mock_state)
        self.assertNotIn("new_registration", mock_state)
        self.assertNotIn("verified_incoming", mock_state)
        self.assertNotIn("login_pass_input", mock_state)
        self.assertNotIn("reg_pass", mock_state)
        self.assertNotIn("new_cred_pass_input", mock_state)
        self.assertNotIn("edit_pwd_123", mock_state)
        self.assertNotIn("custom_cover_bytes", mock_state)

    def test_inactivity_timeout_triggers_cleanup(self) -> None:
        mock_state = {
            "authenticated": True,
            "username": "alice",
            "vault_key": b"\x01" * 32,
            "last_activity_time": time.time() - 301,  # 301s ago (> 300s)
        }

        timed_out = check_inactivity_timeout(mock_state)
        self.assertTrue(timed_out)
        self.assertFalse(mock_state["authenticated"])
        self.assertTrue(mock_state.get("session_timed_out"))


if __name__ == "__main__":
    unittest.main()
