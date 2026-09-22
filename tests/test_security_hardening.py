from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from auth.hashing import hash_password
from auth.session import (
    cleanup_session_state,
    is_locked_out,
    record_failed_attempt,
    reset_failed_attempts,
)
from auth.totp import generate_secret, get_current_code_for_testing, verify_code_with_replay_prevention
from sharing.keys import generate_keypair
from sharing.pgp_exchange import VerificationError, create_package, open_package
from stego.embed import MAX_PAYLOAD_SIZE, create_sample_cover_image, embed_bytes
from vault.crypto import (
    AuthenticationFailedError,
    decrypt_aead,
    derive_vault_key,
    encrypt_aead,
)
from vault.models import Credential
from vault.store import StoreSecurityError, VaultStore, validate_username


class TestNegativeSecurityHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.store = VaultStore(root=self.temp_dir)
        self.username = "alice_sec"
        self.password = "AliceMasterPassword!2026"
        reset_failed_attempts(self.username)

    def tearDown(self) -> None:
        reset_failed_attempts(self.username)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ciphertext_bit_flipping_fails_aead(self) -> None:
        """Negative Test: Tampering with AES-GCM ciphertext must be detected by auth tag."""
        key = derive_vault_key(self.password, os.urandom(16))
        payload = encrypt_aead(b"Super confidential secret", key)

        # Flip a bit in the ciphertext
        raw_ct = list(payload["ciphertext"])
        raw_ct[4] = "Z" if raw_ct[4] != "Z" else "Y"
        payload["ciphertext"] = "".join(raw_ct)

        with self.assertRaises(AuthenticationFailedError):
            decrypt_aead(payload, key)

    def test_metadata_aad_tampering_fails_aead(self) -> None:
        """Negative Test: Altering bound AAD metadata (e.g. username splicing) must fail authentication."""
        key = derive_vault_key(self.password, os.urandom(16))
        correct_aad = b"sentinelvault:vault:v2:alice_sec"
        forged_aad = b"sentinelvault:vault:v2:bob_sec"

        payload = encrypt_aead(b"Secret entries", key, aad=correct_aad)

        with self.assertRaises(AuthenticationFailedError):
            decrypt_aead(payload, key, aad=forged_aad)

    def test_forged_backup_cannot_overwrite_existing_account(self) -> None:
        """Negative Test: Unauthenticated recovery must refuse to overwrite an existing account on disk."""
        priv_pem, pub_pem = generate_keypair(2048)
        totp_secret = generate_secret()
        # Create genuine Alice account
        self.store.create_user(
            username=self.username,
            password=self.password,
            password_hash=hash_password(self.password),
            totp_secret=totp_secret,
            private_key=priv_pem,
            public_key=pub_pem,
        )

        # Attacker creates a forged backup envelope with their own attacker password
        attacker_store = VaultStore(root=tempfile.mkdtemp())
        attacker_user = attacker_store.create_user(
            username=self.username,
            password="AttackerPassword123!",
            password_hash=hash_password("AttackerPassword123!"),
            totp_secret=generate_secret(),
            private_key=priv_pem,
            public_key=pub_pem,
        )
        forged_envelope = attacker_store.create_backup_envelope(
            attacker_user, "AttackerPassword123!")

        # Attacker attempts to upload forged envelope into Alice's store via disaster recovery
        with self.assertRaises(StoreSecurityError) as ctx:
            self.store.restore_backup_envelope(
                blob=forged_envelope,
                password="AttackerPassword123!",
                totp_code="123456",
                is_in_session=False,
            )
        self.assertIn("already exists on this machine",
                      str(ctx.exception).lower())

    def test_in_session_backup_cannot_restore_to_different_username(self) -> None:
        """Negative Test: A logged-in user cannot restore a backup belonging to a different user."""
        priv_pem, pub_pem = generate_keypair(2048)
        alice = self.store.create_user(
            username="alice",
            password=self.password,
            password_hash=hash_password(self.password),
            totp_secret=generate_secret(),
            private_key=priv_pem,
            public_key=pub_pem,
        )
        alice_backup = self.store.create_backup_envelope(alice, self.password)

        # Logged-in user "bob" tries to restore Alice's backup into Bob's vault
        with self.assertRaises(StoreSecurityError) as ctx:
            self.store.restore_backup_envelope(
                blob=alice_backup,
                password=self.password,
                is_in_session=True,
                current_username="bob",
            )
        self.assertIn("cannot restore into active user",
                      str(ctx.exception).lower())

    def test_otp_brute_force_triggers_lockout(self) -> None:
        """Negative Test: 5 consecutive failed OTP attempts must strictly lock out the user."""
        self.assertFalse(is_locked_out(self.username)[0])

        for attempt in range(1, 5):
            count, newly_locked = record_failed_attempt(self.username)
            self.assertEqual(count, attempt)
            self.assertFalse(newly_locked)
            self.assertFalse(is_locked_out(self.username)[0])

        # 5th failed attempt triggers lockout
        count, newly_locked = record_failed_attempt(self.username)
        self.assertEqual(count, 5)
        self.assertTrue(newly_locked)

        locked, remaining = is_locked_out(self.username)
        self.assertTrue(locked)
        self.assertGreater(remaining, 0)

    def test_totp_replay_rejection(self) -> None:
        """Negative Test: An observed OTP code cannot be replayed within the same time-step."""
        secret = generate_secret()
        code = get_current_code_for_testing(secret)

        valid, step = verify_code_with_replay_prevention(
            secret, code, last_verified_timestep=0)
        self.assertTrue(valid)

        # Attacker tries to replay same code
        valid_replay, _ = verify_code_with_replay_prevention(
            secret, code, last_verified_timestep=step)
        self.assertFalse(valid_replay)

    def test_pgp_key_substitution_detected(self) -> None:
        """Negative Test: Signing with one key and attempting to verify with another must fail."""
        alice_priv, alice_pub = generate_keypair(2048)
        bob_priv, bob_pub = generate_keypair(2048)
        eve_priv, eve_pub = generate_keypair(2048)

        package = create_package(
            payload=b"Important message",
            recipient_public_pem=bob_pub,
            sender_private_pem=alice_priv,
            sender_username="alice",
        )

        # Attempt verification against Eve's public key instead of Alice's
        with self.assertRaises(VerificationError):
            open_package(package, recipient_private_pem=bob_priv,
                         sender_public_pem=eve_pub)

    def test_pgp_signature_tampering_rejected(self) -> None:
        """Negative Test: Tampering with signature string must fail verification."""
        alice_priv, alice_pub = generate_keypair(2048)
        bob_priv, bob_pub = generate_keypair(2048)

        package = create_package(
            payload=b"Critical wire transfer details",
            recipient_public_pem=bob_pub,
            sender_private_pem=alice_priv,
            sender_username="alice",
        )

        data = json.loads(package.decode("utf-8"))
        # Tamper with signature
        sig_chars = list(data["signature"])
        sig_chars[10] = "X" if sig_chars[10] != "X" else "Y"
        data["signature"] = "".join(sig_chars)

        with self.assertRaises(VerificationError):
            open_package(json.dumps(data).encode("utf-8"), bob_priv, alice_pub)

    def test_oversized_payload_rejection(self) -> None:
        """Negative Test: Payloads exceeding 5 MB must be rejected by stego and sharing."""
        cover = create_sample_cover_image(200, 200)
        oversized = b"X" * (MAX_PAYLOAD_SIZE + 1024)

        with self.assertRaises(ValueError) as ctx:
            embed_bytes(cover, oversized)
        self.assertIn("exceeds maximum allowed size",
                      str(ctx.exception).lower())

    def test_username_path_traversal_rejected(self) -> None:
        """Negative Test: Path traversal attempts in username must be rejected."""
        invalid_usernames = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "alice/bob",
            "alice\\bob",
            "al",           # too short (<3)
            "a" * 35,       # too long (>32)
            "user with spaces",
            "user$name",
            "",
        ]
        for bad_user in invalid_usernames:
            with self.assertRaises(StoreSecurityError):
                validate_username(bad_user)

    def test_logout_cleanup_purges_all_sensitive_data(self) -> None:
        """Negative Test: Sensitive data audit after logout ensures zero secrets remain in state."""
        state = {
            "authenticated": True,
            "username": "alice",
            "password": "MasterPassword123!",
            "vault_key": b"\x00" * 32,
            "pending_password": "PlaintextPassword!",
            "new_registration": {"secret": "TOTPSECRET"},
            "verified_incoming": [{"site": "github.com", "password": "PlainTextToken"}],
            "login_pass_input": "typed_master_pwd",
            "reg_pass": "typed_reg_pwd",
            "new_cred_pass_input": "typed_cred_pwd",
            "edit_pwd_site1": "typed_edit_pwd",
        }

        cleanup_session_state(state)

        # Audit keys
        prohibited_substrings = ["pass", "secret", "key", "verified_incoming"]
        for key in state:
            if key in ("authenticated", "username"):
                continue
            for sub in prohibited_substrings:
                self.assertNotIn(
                    sub, key.lower(), f"Prohibited key '{key}' still in state after cleanup!")

        self.assertFalse(state["authenticated"])
        self.assertEqual(state["username"], "")


if __name__ == "__main__":
    unittest.main()
