from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sharing.keys import get_key_fingerprint, load_private_key, load_public_key
from stego.embed import create_sample_cover_image, embed_bytes
from stego.extract import extract_bytes

MAX_PACKAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB limit


class VerificationError(Exception):
    """Raised when digital signature verification fails."""
    pass


class DecryptionError(Exception):
    """Raised when asymmetric or AEAD decryption fails."""
    pass


def create_package(
    payload: bytes,
    recipient_public_pem: str,
    sender_private_pem: str,
    sender_username: str = "Anonymous",
) -> bytes:
    """
    Create a PGP-style hybrid encrypted and digitally signed package.
    1. Symmetric: Encrypts payload with an ephemeral 256-bit AES session key using AES-256-GCM (AEAD).
    2. Asymmetric Confidentiality: Encrypts the AES session key with recipient's RSA public key (OAEP-SHA256).
    3. Asymmetric Authentication: Digitally signs the package with sender's RSA private key (PSS-SHA256).
    """
    if not payload:
        raise ValueError("Payload cannot be empty")
    if len(payload) > MAX_PACKAGE_SIZE_BYTES:
        raise ValueError("Payload exceeds maximum size limit (5 MB).")

    recipient_key = load_public_key(recipient_public_pem)
    sender_key = load_private_key(sender_private_pem)

    # 1. Ephemeral AES-256 session key and 12-byte nonce
    session_key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"sentinelvault_pgp_v2"

    # AES-256-GCM AEAD encrypt payload
    aesgcm = AESGCM(session_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, payload, aad)

    # 2. Encrypt AES session key with recipient's RSA public key (OAEP)
    encrypted_session_key = recipient_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Create digest buffer to sign: format + encrypted_key + nonce + ciphertext
    sign_buffer = (
        b"SENTINEL_PGP_V2:"
        + encrypted_session_key
        + b":"
        + nonce
        + b":"
        + ciphertext_and_tag
    )

    # Digitally sign with sender's private key (PSS)
    signature = sender_key.sign(
        sign_buffer,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    package_dict = {
        "format": "sentinelvault_pgp",
        "version": 2,
        "algorithm": "AES-256-GCM + RSA-OAEP + RSA-PSS",
        "sender": sender_username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext_and_tag).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    return json.dumps(package_dict, indent=2).encode("utf-8")


def open_package(
    package: bytes,
    recipient_private_pem: str,
    sender_public_pem: str,
) -> Tuple[bytes, dict]:
    """
    Open and verify a PGP-style package:
    1. Authenticate sender: Verifies digital signature with sender's RSA public key.
    2. Decrypt session key: Decrypts AES session key using recipient's RSA private key.
    3. Decrypt & authenticate payload: Decrypts AES-256-GCM ciphertext and validates auth tag.
    Returns (decrypted_payload_bytes, metadata_dict).
    """
    if len(package) > MAX_PACKAGE_SIZE_BYTES:
        raise ValueError("Package exceeds maximum allowed size (5 MB).")

    try:
        data = json.loads(package.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid package format: not valid JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("Malformed package data.")

    required = ["encrypted_session_key", "nonce", "ciphertext", "signature"]
    for field in required:
        if field not in data:
            raise ValueError(f"Malformed package: missing '{field}'")

    encrypted_session_key = base64.b64decode(data["encrypted_session_key"])
    nonce = base64.b64decode(data["nonce"])
    ciphertext_and_tag = base64.b64decode(data["ciphertext"])
    signature = base64.b64decode(data["signature"])

    # 1. Verify digital signature first (Authentication & Integrity)
    sign_buffer = (
        b"SENTINEL_PGP_V2:"
        + encrypted_session_key
        + b":"
        + nonce
        + b":"
        + ciphertext_and_tag
    )

    try:
        sender_key = load_public_key(sender_public_pem)
        sender_key.verify(
            signature,
            sign_buffer,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise VerificationError(
            "Digital signature verification FAILED! The package was modified or not signed by this sender."
        ) from exc

    # 2. Decrypt session key with recipient's private key (Confidentiality)
    try:
        recipient_key = load_private_key(recipient_private_pem)
        session_key = recipient_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise DecryptionError(
            "Decryption failed! You do not have the matching RSA private key for this recipient."
        ) from exc

    # 3. Decrypt & verify AEAD payload with session key
    try:
        aesgcm = AESGCM(session_key)
        payload = aesgcm.decrypt(
            nonce, ciphertext_and_tag, b"sentinelvault_pgp_v2")
    except Exception as exc:
        raise DecryptionError(
            "Failed to decrypt payload using decrypted session key: auth tag verification failed.") from exc

    metadata = {
        "sender": data.get("sender", "Unknown"),
        "timestamp": data.get("timestamp", ""),
        "sender_fingerprint": get_key_fingerprint(sender_public_pem),
        "verified": True,
    }

    return payload, metadata


def create_stego_share_package(
    package_bytes: bytes,
    cover_image_bytes: Optional[bytes] = None,
) -> bytes:
    """Convenience helper to embed a PGP package inside a cover PNG for covert sharing."""
    if not cover_image_bytes:
        cover_image_bytes = create_sample_cover_image(600, 600)
    return embed_bytes(cover_image_bytes, package_bytes)


def open_stego_share_package(stego_image_bytes: bytes) -> bytes:
    """Convenience helper to extract PGP package bytes from a stego PNG image."""
    return extract_bytes(stego_image_bytes)
