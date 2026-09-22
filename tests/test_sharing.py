from __future__ import annotations

import json
import shutil
import tempfile
import unittest

from sharing.keys import TrustedKeyStore, generate_keypair, get_key_fingerprint
from sharing.pgp_exchange import (
    DecryptionError,
    VerificationError,
    create_package,
    create_stego_share_package,
    open_package,
    open_stego_share_package,
)


class TestPGPSharingAEAD(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.alice_priv, self.alice_pub = generate_keypair(2048)
        self.bob_priv, self.bob_pub = generate_keypair(2048)
        self.eve_priv, self.eve_pub = generate_keypair(2048)

        self.sample_payload = json.dumps([
            {"site": "github.com", "username": "alice",
                "password": "SuperSecretToken!"},
            {"site": "bank.com", "username": "alice_bank",
                "password": "PIN9876Account!"},
        ]).encode("utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_key_fingerprint_standard_format(self) -> None:
        fp = get_key_fingerprint(self.alice_pub)
        self.assertTrue(fp.startswith("SHA256:"))
        parts = fp.replace("SHA256:", "").split(":")
        self.assertEqual(len(parts), 16)

    def test_trusted_key_pinning_and_substitution_warning(self) -> None:
        trusted_store = TrustedKeyStore(self.temp_dir)
        # Trust Bob's key initially
        pinned_fp = trusted_store.trust_key("bob", self.bob_pub)
        self.assertTrue(pinned_fp.startswith("SHA256:"))

        # Verify Bob's key matches pinned fingerprint
        is_trusted, msg = trusted_store.verify_trust("bob", self.bob_pub)
        self.assertTrue(is_trusted)
        self.assertIn("verified", msg.lower())

        # An attacker substitutes Bob's key with Eve's key
        is_trusted_sub, warn_msg = trusted_store.verify_trust(
            "bob", self.eve_pub)
        self.assertFalse(is_trusted_sub)
        self.assertIn("key substitution detected", warn_msg.lower())

    def test_pgp_hybrid_aead_roundtrip(self) -> None:
        pkg_bytes = create_package(
            payload=self.sample_payload,
            recipient_public_pem=self.bob_pub,
            sender_private_pem=self.alice_priv,
            sender_username="alice",
        )

        opened_payload, meta = open_package(
            package=pkg_bytes,
            recipient_private_pem=self.bob_priv,
            sender_public_pem=self.alice_pub,
        )

        self.assertEqual(opened_payload, self.sample_payload)
        self.assertEqual(meta["sender"], "alice")
        self.assertTrue(meta["verified"])
        self.assertTrue(meta["sender_fingerprint"].startswith("SHA256:"))

    def test_pgp_tamper_signature_rejected(self) -> None:
        pkg_bytes = create_package(
            payload=self.sample_payload,
            recipient_public_pem=self.bob_pub,
            sender_private_pem=self.alice_priv,
            sender_username="alice",
        )

        data = json.loads(pkg_bytes.decode("utf-8"))
        # Tamper with ciphertext
        data["ciphertext"] = data["ciphertext"][:-4] + "AAAA"
        tampered_pkg = json.dumps(data).encode("utf-8")

        with self.assertRaises(VerificationError):
            open_package(tampered_pkg, self.bob_priv, self.alice_pub)

    def test_pgp_wrong_sender_public_key_rejected(self) -> None:
        pkg_bytes = create_package(
            payload=self.sample_payload,
            recipient_public_pem=self.bob_pub,
            sender_private_pem=self.alice_priv,
            sender_username="alice",
        )

        with self.assertRaises(VerificationError):
            open_package(pkg_bytes, self.bob_priv, self.eve_pub)

    def test_pgp_unauthorized_recipient_rejected(self) -> None:
        pkg_bytes = create_package(
            payload=self.sample_payload,
            recipient_public_pem=self.bob_pub,
            sender_private_pem=self.alice_priv,
            sender_username="alice",
        )

        with self.assertRaises(DecryptionError):
            open_package(pkg_bytes, self.eve_priv, self.alice_pub)

    def test_pgp_steganographic_package_roundtrip(self) -> None:
        pkg_bytes = create_package(
            payload=self.sample_payload,
            recipient_public_pem=self.bob_pub,
            sender_private_pem=self.alice_priv,
            sender_username="alice",
        )
        stego_png = create_stego_share_package(pkg_bytes)
        self.assertTrue(stego_png.startswith(b"\x89PNG\r\n\x1a\n"))

        extracted_pkg = open_stego_share_package(stego_png)
        opened_payload, meta = open_package(
            extracted_pkg, self.bob_priv, self.alice_pub)
        self.assertEqual(opened_payload, self.sample_payload)


if __name__ == "__main__":
    unittest.main()
