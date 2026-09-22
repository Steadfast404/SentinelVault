from __future__ import annotations

import os
import unittest

from vault.crypto import (
    AuthenticationFailedError,
    CryptographicError,
    decrypt_aead,
    decrypt_text,
    derive_backup_key,
    derive_key_with_domain,
    derive_private_key_encryption_key,
    derive_vault_key,
    encrypt_aead,
    encrypt_text,
    evaluate_password_strength,
    generate_password,
)


class TestVaultCryptoAEAD(unittest.TestCase):
    def setUp(self) -> None:
        self.password = "SuperSecretMasterKey123!"
        self.salt = os.urandom(16)
        self.vault_key = derive_vault_key(self.password, self.salt)

    def test_domain_separated_key_derivations(self) -> None:
        # Derived keys must be 32 bytes (256 bits)
        self.assertEqual(len(self.vault_key), 32)
        priv_key = derive_private_key_encryption_key(self.password, self.salt)
        backup_key = derive_backup_key(self.password, self.salt)

        self.assertEqual(len(priv_key), 32)
        self.assertEqual(len(backup_key), 32)

        # Domain separation ensures keys for different purposes are completely distinct
        self.assertNotEqual(self.vault_key, priv_key)
        self.assertNotEqual(self.vault_key, backup_key)
        self.assertNotEqual(priv_key, backup_key)

    def test_aes_gcm_aead_roundtrip_with_aad(self) -> None:
        data = b"Sensitive Vault Credential Data Payload \x00\xff"
        aad = b"sentinelvault:vault:v2:alice"

        payload = encrypt_aead(data, self.vault_key, aad)
        self.assertEqual(payload["algorithm"], "AES-256-GCM")
        self.assertIn("nonce", payload)
        self.assertIn("ciphertext", payload)

        decrypted = decrypt_aead(payload, self.vault_key, aad)
        self.assertEqual(decrypted, data)

    def test_aes_gcm_fresh_nonce_per_encryption(self) -> None:
        data = b"Repeated Data"
        p1 = encrypt_aead(data, self.vault_key)
        p2 = encrypt_aead(data, self.vault_key)
        # Nonces and ciphertexts must be distinct
        self.assertNotEqual(p1["nonce"], p2["nonce"])
        self.assertNotEqual(p1["ciphertext"], p2["ciphertext"])

    def test_aes_gcm_tampered_ciphertext_fails_auth(self) -> None:
        data = b"Important Financial Credentials"
        payload = encrypt_aead(data, self.vault_key)

        # Tamper with one character of base64 ciphertext
        corrupted_ct = list(payload["ciphertext"])
        corrupted_ct[5] = "A" if corrupted_ct[5] != "A" else "B"
        payload["ciphertext"] = "".join(corrupted_ct)

        with self.assertRaises(AuthenticationFailedError):
            decrypt_aead(payload, self.vault_key)

    def test_aes_gcm_tampered_aad_fails_auth(self) -> None:
        data = b"Cross-User Vault Payload"
        alice_aad = b"sentinelvault:vault:v2:alice"
        bob_aad = b"sentinelvault:vault:v2:bob"

        payload = encrypt_aead(data, self.vault_key, alice_aad)

        # Attacker tries to splice Alice's ciphertext into Bob's vault
        with self.assertRaises(AuthenticationFailedError):
            decrypt_aead(payload, self.vault_key, bob_aad)

    def test_encrypt_text_roundtrip(self) -> None:
        text = "https://github.com | alice | P@ssw0rd!#$%"
        encrypted = encrypt_text(text, self.vault_key)
        self.assertIn(":", encrypted)
        self.assertNotIn(text, encrypted)

        decrypted = decrypt_text(encrypted, self.vault_key)
        self.assertEqual(decrypted, text)

    def test_password_generator_and_strength(self) -> None:
        pwd = generate_password(length=20, use_upper=True,
                                use_lower=True, use_digits=True, use_symbols=True)
        self.assertEqual(len(pwd), 20)
        score, label, _ = evaluate_password_strength(pwd)
        self.assertGreaterEqual(score, 70)
        self.assertIn(label, ("Good", "Very Strong"))

        w_score, w_label, _ = evaluate_password_strength("abc")
        self.assertLess(w_score, 40)
        self.assertEqual(w_label, "Weak")


if __name__ == "__main__":
    unittest.main()
