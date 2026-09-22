from __future__ import annotations

import json
import shutil
import tempfile
import unittest

from auth.hashing import hash_password
from auth.session import authenticate
from auth.totp import generate_secret, get_current_code_for_testing
from sharing.keys import generate_keypair
from sharing.pgp_exchange import create_package, open_package
from stego.embed import create_sample_cover_image, embed_bytes
from stego.extract import extract_bytes
from vault.crypto import derive_vault_key
from vault.models import Credential
from vault.store import VaultStore
import base64


class TestSentinelVaultEndToEndAEAD(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.store = VaultStore(root=self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_hardened_demo_script_workflow(self) -> None:
        # -------------------------------------------------------------
        # Step 1: User Registration (Alice)
        # -------------------------------------------------------------
        username = "alice"
        password = "MasterPasswordSecure2026!"
        totp_secret = generate_secret()
        private_pem, public_pem = generate_keypair(2048)

        user_alice = self.store.create_user(
            username=username,
            password=password,
            password_hash=hash_password(password),
            totp_secret=totp_secret,
            private_key=private_pem,
            public_key=public_pem,
        )
        self.assertIsNotNone(user_alice)
        self.assertTrue(self.store.user_path(username).exists())

        # -------------------------------------------------------------
        # Step 2: Attempt login with correct password but wrong OTP -> Denied
        # -------------------------------------------------------------
        valid_otp = get_current_code_for_testing(totp_secret)
        wrong_otp = "000000" if valid_otp != "000000" else "111111"
        self.assertFalse(authenticate(user_alice, password, wrong_otp))

        # -------------------------------------------------------------
        # Step 3: Login correctly -> Add sample credentials
        # -------------------------------------------------------------
        self.assertTrue(authenticate(user_alice, password, valid_otp))

        salt = base64.b64decode(user_alice["vault_salt"])
        vault_key = derive_vault_key(password, salt)

        sample_creds = [
            Credential(site="github.com", username="alice_dev",
                       password="ghp_SecretTokenXYZ987"),
            Credential(site="mail.secure.org",
                       username="alice@mail.com", password="SuperEmailPass#1"),
            Credential(site="crypto-exchange.io",
                       username="alice_trader", password="TradeP@ssword99"),
        ]
        self.store.write_credentials(user_alice, vault_key, sample_creds)
        self.store.save_user(username, user_alice)

        # -------------------------------------------------------------
        # Step 4: Storage check: Verify AES-256-GCM AEAD at rest
        # -------------------------------------------------------------
        disk_raw = self.store.user_path(username).read_text(encoding="utf-8")
        self.assertNotIn("ghp_SecretTokenXYZ987", disk_raw)
        self.assertNotIn("SuperEmailPass#1", disk_raw)
        self.assertNotIn(password, disk_raw)

        parsed_disk = json.loads(disk_raw)
        self.assertEqual(parsed_disk["vault"]["algorithm"], "AES-256-GCM")
        self.assertIn("nonce", parsed_disk["vault"])
        self.assertIn("ciphertext", parsed_disk["vault"])
        self.assertEqual(parsed_disk["private_key"]
                         ["algorithm"], "AES-256-GCM")

        # -------------------------------------------------------------
        # Step 5: Export authenticated backup to PNG (Steganography)
        # -------------------------------------------------------------
        cover_image = create_sample_cover_image(512, 512)
        backup_envelope = self.store.create_backup_envelope(
            user_alice, password)
        stego_png = embed_bytes(cover_image, backup_envelope)
        self.assertTrue(stego_png.startswith(b"\x89PNG\r\n\x1a\n"))

        # -------------------------------------------------------------
        # Step 6: Disaster Recovery -> Delete vault, restore from PNG
        # -------------------------------------------------------------
        # Wipe local vault file completely
        self.assertTrue(self.store.delete_user(username))
        self.assertIsNone(self.store.load_user(username))

        # Restore from stego PNG with authentication
        extracted_envelope = extract_bytes(stego_png)
        current_otp = get_current_code_for_testing(totp_secret)
        restored_user = self.store.restore_backup_envelope(
            blob=extracted_envelope,
            password=password,
            totp_code=current_otp,
            is_in_session=False,
        )
        self.assertIsNotNone(restored_user)
        self.assertTrue(self.store.user_path(username).exists())

        # Verify credentials recovered
        recovered_salt = base64.b64decode(restored_user["vault_salt"])
        recovered_vault_key = derive_vault_key(password, recovered_salt)
        recovered_creds = self.store.read_credentials(
            restored_user, recovered_vault_key)
        self.assertEqual(len(recovered_creds), 3)
        self.assertEqual(recovered_creds[0].site, "github.com")
        self.assertEqual(recovered_creds[0].password, "ghp_SecretTokenXYZ987")

        # -------------------------------------------------------------
        # Step 7: Simulate Second User (Bob) and Hybrid PGP Vault Sharing
        # -------------------------------------------------------------
        bob_priv, bob_pub = generate_keypair(2048)
        user_bob = self.store.create_user(
            username="bob",
            password="BobMasterPassword456!",
            password_hash=hash_password("BobMasterPassword456!"),
            totp_secret=generate_secret(),
            private_key=bob_priv,
            public_key=bob_pub,
        )

        # Alice shares github credential with Bob
        creds_to_share = [recovered_creds[0].to_dict()]
        alice_priv = self.store.private_key(restored_user, password)

        share_package = create_package(
            payload=json.dumps(creds_to_share).encode("utf-8"),
            recipient_public_pem=bob_pub,
            sender_private_pem=alice_priv,
            sender_username="alice",
        )

        # Bob verifies signature and decrypts with AEAD
        decrypted_payload, meta = open_package(
            package=share_package,
            recipient_private_pem=bob_priv,
            sender_public_pem=restored_user["public_key"],
        )
        self.assertTrue(meta["verified"])
        self.assertEqual(meta["sender"], "alice")

        shared_items = json.loads(decrypted_payload.decode("utf-8"))
        self.assertEqual(len(shared_items), 1)
        self.assertEqual(shared_items[0]["site"], "github.com")
        self.assertEqual(shared_items[0]["password"], "ghp_SecretTokenXYZ987")


if __name__ == "__main__":
    unittest.main()
