from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """Generate an RSA keypair (private and public PEM strings)."""
    private = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def load_private_key(pem: str):
    """Load RSA private key from PEM string."""
    try:
        return serialization.load_pem_private_key(pem.strip().encode("ascii"), password=None)
    except Exception as exc:
        raise ValueError(f"Invalid private key format: {exc}") from exc


def load_public_key(pem: str):
    """Load RSA public key from PEM string."""
    try:
        return serialization.load_pem_public_key(pem.strip().encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid public key format: {exc}") from exc


def get_key_fingerprint(public_pem: str) -> str:
    """
    Generate SHA-256 fingerprint for a public key (formatted in colons).
    Standard format: SHA256:XX:XX:...
    """
    try:
        clean = public_pem.strip().encode("ascii")
        digest = hashlib.sha256(clean).hexdigest().upper()
        formatted = ":".join(digest[i: i + 2] for i in range(0, 32, 2))
        return f"SHA256:{formatted}"
    except Exception:
        return "UNKNOWN_FINGERPRINT"


class TrustedKeyStore:
    """Manages trusted public-key fingerprints and identity bindings."""

    def __init__(self, root: Path | str = ".sentinelvault") -> None:
        self.file_path = Path(root) / "trusted_contacts.json"

    def _load(self) -> Dict[str, dict]:
        if not self.file_path.exists():
            return {}
        try:
            return json.loads(self.file_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self, data: Dict[str, dict]) -> None:
        self.file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_contact(self, contact_name: str) -> Optional[dict]:
        contacts = self._load()
        return contacts.get(contact_name.strip().lower())

    def trust_key(self, contact_name: str, public_pem: str) -> str:
        contacts = self._load()
        fp = get_key_fingerprint(public_pem)
        contacts[contact_name.strip().lower()] = {
            "contact_name": contact_name.strip(),
            "public_key": public_pem.strip(),
            "fingerprint": fp,
        }
        self._save(contacts)
        return fp

    def verify_trust(self, contact_name: str, public_pem: str) -> Tuple[bool, str]:
        """
        Verify whether the given public key matches the pinned fingerprint for this contact.
        Returns (is_trusted, message).
        """
        contact = self.get_contact(contact_name)
        current_fp = get_key_fingerprint(public_pem)
        if not contact:
            return False, f"Contact '{contact_name}' is not in your trusted contacts list (Fingerprint: {current_fp})."

        trusted_fp = contact.get("fingerprint")
        if trusted_fp != current_fp:
            return False, (
                f"SECURITY WARNING: Key substitution detected for '{contact_name}'! "
                f"Pinned: {trusted_fp}, Received: {current_fp}."
            )

        return True, f"Key verified and trusted for '{contact_name}'."

    def list_contacts(self) -> Dict[str, dict]:
        """List all trusted contacts and their pinned fingerprints."""
        return self._load()

    def remove_contact(self, contact_name: str) -> bool:
        """Remove a trusted contact from the store."""
        contacts = self._load()
        key = contact_name.strip().lower()
        if key in contacts:
            del contacts[key]
            self._save(contacts)
            return True
        return False
