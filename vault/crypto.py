from __future__ import annotations

import base64
import math
import os
import secrets
import string
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12  # 96 bits for AES-GCM
KEY_SIZE = 32    # 256 bits for AES-256-GCM


class CryptographicError(Exception):
    """Base exception for cryptographic failures."""
    pass


class AuthenticationFailedError(CryptographicError):
    """Raised when AEAD tag verification fails or data is tampered with."""
    pass


def derive_key_with_domain(password: str, salt: bytes, domain: str) -> bytes:
    """
    Derive a 256-bit key using PBKDF2-HMAC-SHA256 with domain separation.
    Domain separation prevents key reuse across distinct subsystem purposes.
    """
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")
    domain_salt = salt + domain.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=domain_salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_vault_key(password: str, salt: bytes) -> bytes:
    """Derive key dedicated for vault credential encryption at rest."""
    return derive_key_with_domain(password, salt, "sentinelvault:vault-encryption:v2")


def derive_private_key_encryption_key(password: str, salt: bytes) -> bytes:
    """Derive key dedicated for encrypting the user's RSA private identity key."""
    return derive_key_with_domain(password, salt, "sentinelvault:private-key-encryption:v2")


def derive_backup_key(password: str, salt: bytes) -> bytes:
    """Derive key dedicated for encrypting and authenticating backup envelopes."""
    return derive_key_with_domain(password, salt, "sentinelvault:backup-envelope:v2")


# Backward-compatible alias
def derive_key(password: str, salt: bytes) -> bytes:
    return derive_vault_key(password, salt)


def encrypt_aead(data: bytes, key: bytes, aad: bytes = b"") -> dict[str, str]:
    """
    Encrypt data using AES-256-GCM (AEAD).
    Generates a fresh 12-byte nonce per encryption and authenticates both data and AAD.
    Returns dictionary with base64-encoded nonce, ciphertext (including 16-byte tag), and algorithm.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE} bytes")
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, aad)
    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext_and_tag).decode("ascii"),
    }


def decrypt_aead(payload: dict[str, str], key: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.
    Authenticates the ciphertext, auth tag, and Additional Authenticated Data (AAD).
    Raises AuthenticationFailedError if modified, corrupted, or tag mismatch occurs.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE} bytes")
    if "nonce" not in payload or "ciphertext" not in payload:
        raise CryptographicError(
            "Malformed payload: missing 'nonce' or 'ciphertext'")

    try:
        nonce = base64.b64decode(payload["nonce"])
        ciphertext_and_tag = base64.b64decode(payload["ciphertext"])
        if len(nonce) != NONCE_SIZE:
            raise CryptographicError(
                f"Invalid nonce length: expected {NONCE_SIZE} bytes")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise AuthenticationFailedError(
            "AEAD authentication failed! Ciphertext or metadata has been tampered with.") from exc
    except Exception as exc:
        if isinstance(exc, (AuthenticationFailedError, CryptographicError)):
            raise
        raise CryptographicError(f"Decryption failed: {exc}") from exc


# Compatible wrappers for store.py and other callers
def encrypt_bytes(data: bytes, key: bytes, aad: bytes = b"") -> dict[str, str]:
    return encrypt_aead(data, key, aad)


def decrypt_bytes(payload: dict[str, str], key: bytes, aad: bytes = b"") -> bytes:
    return decrypt_aead(payload, key, aad)


def encrypt_text(text: str, key: bytes, aad: bytes = b"") -> str:
    """Encrypt UTF-8 text using AEAD into NONCE:CIPHERTEXT format."""
    payload = encrypt_aead(text.encode("utf-8"), key, aad)
    return f"{payload['nonce']}:{payload['ciphertext']}"


def decrypt_text(value: str, key: bytes, aad: bytes = b"") -> str:
    """Decrypt NONCE:CIPHERTEXT formatted AEAD string."""
    parts = value.split(":", 1)
    if len(parts) != 2:
        raise CryptographicError("Malformed encrypted text format")
    nonce, ciphertext = parts
    return decrypt_aead({"nonce": nonce, "ciphertext": ciphertext}, key, aad).decode("utf-8")


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate cryptographically secure random password."""
    pools = []
    guaranteed = []
    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        special_chars = "!@#$%^&*()-_=+[]{}<>?"
        pools.append(special_chars)
        guaranteed.append(secrets.choice(special_chars))

    if not pools:
        pools = [string.ascii_letters + string.digits]
        guaranteed = [secrets.choice(pools[0])]

    all_chars = "".join(pools)
    remaining_length = max(0, length - len(guaranteed))
    password_chars = guaranteed + \
        [secrets.choice(all_chars) for _ in range(remaining_length)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def evaluate_password_strength(password: str) -> Tuple[int, str, str]:
    """
    Evaluate password strength.
    Returns (score_percentage: 0-100, label: str, feedback: str).
    """
    if not password:
        return 0, "Empty", "Please enter a password"

    length = len(password)
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    entropy = length * (math.log2(charset_size) if charset_size > 0 else 0)

    if entropy < 36:
        score = min(35, int(entropy / 36 * 35))
        label = "Weak"
        feedback = "Add more length and mix uppercase, digits, or symbols."
    elif entropy < 60:
        score = int(35 + (entropy - 36) / 24 * 35)
        label = "Fair"
        feedback = "Moderate strength. Consider making it longer (14+ characters)."
    elif entropy < 80:
        score = int(70 + (entropy - 60) / 20 * 20)
        label = "Good"
        feedback = "Strong password! Hard to brute force."
    else:
        score = min(100, int(90 + (entropy - 80) / 20 * 10))
        label = "Very Strong"
        feedback = "Excellent entropy and defense against attacks."

    return score, label, feedback
