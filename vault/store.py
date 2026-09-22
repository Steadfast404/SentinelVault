from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import List, Optional, Union

from auth.totp import verify_code
from vault.crypto import (
    AuthenticationFailedError,
    CryptographicError,
    decrypt_aead,
    derive_backup_key,
    derive_private_key_encryption_key,
    derive_vault_key,
    encrypt_aead,
)
from vault.models import Credential

# Enforce strict alphanumeric + underscore/dash username format
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
MAX_BACKUP_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB limit


class StoreSecurityError(Exception):
    """Raised when security boundaries, permissions, or schema checks fail."""
    pass


def validate_username(username: str) -> str:
    """Validate and sanitize username to prevent path traversal or invalid characters."""
    if not username or not isinstance(username, str):
        raise StoreSecurityError("Username cannot be empty")
    cleaned = username.strip()
    if not USERNAME_REGEX.match(cleaned):
        raise StoreSecurityError(
            "Invalid username. Must be 3-32 characters long and contain only letters, digits, '_' or '-'."
        )
    return cleaned


class VaultStore:
    def __init__(self, root: Path | str = ".sentinelvault") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Set restricted directory permissions where supported (POSIX 0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def user_path(self, username: str) -> Path:
        valid_user = validate_username(username)
        return self.root / f"{valid_user.lower()}.json"

    def list_users(self) -> List[str]:
        return [p.stem for p in self.root.glob("*.json")]

    def load_user(self, username: str) -> Optional[dict]:
        try:
            path = self.user_path(username)
        except StoreSecurityError:
            return None

        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return None
            return data
        except (json.JSONDecodeError, OSError):
            return None

    def save_user(self, username: str, user: dict) -> None:
        path = self.user_path(username)
        temporary = path.with_suffix(".tmp")
        payload_str = json.dumps(user, indent=2)
        temporary.write_text(payload_str, encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def delete_user(self, username: str) -> bool:
        path = self.user_path(username)
        if path.exists():
            path.unlink()
            return True
        return False

    def create_user(
        self,
        username: str,
        password: str,
        password_hash: str,
        totp_secret: str,
        private_key: str,
        public_key: str,
    ) -> dict:
        valid_user = validate_username(username)
        salt = os.urandom(16)
        vault_key = derive_vault_key(password, salt)
        priv_enc_key = derive_private_key_encryption_key(password, salt)

        vault_aad = f"sentinelvault:vault:v2:{valid_user.lower()}".encode(
            "utf-8")
        priv_aad = f"sentinelvault:private_key:v2:{valid_user.lower()}".encode(
            "utf-8")

        user = {
            "format": "sentinelvault_user",
            "version": 2,
            "username": valid_user,
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "vault_salt": base64.b64encode(salt).decode("ascii"),
            "vault": encrypt_aead(b"[]", vault_key, vault_aad),
            "private_key": encrypt_aead(private_key.encode("utf-8"), priv_enc_key, priv_aad),
            "public_key": public_key,
        }
        self.save_user(valid_user, user)
        return user

    def _resolve_vault_key(self, user: dict, key_or_password: Union[bytes, str]) -> bytes:
        if isinstance(key_or_password, bytes):
            return key_or_password
        salt = base64.b64decode(user["vault_salt"])
        return derive_vault_key(key_or_password, salt)

    def read_credentials(self, user: dict, key_or_password: Union[bytes, str]) -> List[Credential]:
        """
        Decrypt credentials using AES-256-GCM AEAD.
        Accepts either derived vault key (bytes) or password string.
        """
        vault_key = self._resolve_vault_key(user, key_or_password)
        username = user.get("username", "")
        vault_aad = f"sentinelvault:vault:v2:{username.lower()}".encode(
            "utf-8")

        vault_data = user.get("vault")
        if not vault_data:
            return []

        plaintext = decrypt_aead(vault_data, vault_key, vault_aad)
        raw_list = json.loads(plaintext.decode("utf-8"))
        return [Credential.from_dict(item) for item in raw_list]

    def write_credentials(
        self,
        user: dict,
        key_or_password: Union[bytes, str],
        credentials: List[Credential],
    ) -> None:
        """
        Encrypt and persist credentials using AES-256-GCM AEAD with bound AAD.
        """
        vault_key = self._resolve_vault_key(user, key_or_password)
        username = user.get("username", "")
        vault_aad = f"sentinelvault:vault:v2:{username.lower()}".encode(
            "utf-8")

        raw_bytes = json.dumps([c.to_dict()
                               for c in credentials]).encode("utf-8")
        user["vault"] = encrypt_aead(raw_bytes, vault_key, vault_aad)

    def private_key(self, user: dict, password: str) -> str:
        """
        Decrypt user RSA private key using independent domain-separated key.
        """
        salt = base64.b64decode(user["vault_salt"])
        priv_enc_key = derive_private_key_encryption_key(password, salt)
        username = user.get("username", "")
        priv_aad = f"sentinelvault:private_key:v2:{username.lower()}".encode(
            "utf-8")

        priv_data = user["private_key"]
        return decrypt_aead(priv_data, priv_enc_key, priv_aad).decode("utf-8")

    def create_backup_envelope(self, user: dict, password: str) -> bytes:
        """
        Create a versioned, authenticated backup envelope using AES-256-GCM.
        Protects credentials, salt, TOTP secret, and keys.
        """
        username = user.get("username", "")
        salt = base64.b64decode(user["vault_salt"])
        vault_key = derive_vault_key(password, salt)

        # Decrypt credentials in memory to bundle into backup
        credentials = self.read_credentials(user, vault_key)
        private_pem = self.private_key(user, password)

        backup_salt = os.urandom(16)
        backup_key = derive_backup_key(password, backup_salt)
        iso_timestamp = datetime.now(timezone.utc).isoformat()

        aad = f"sentinelvault:backup:v2:{username.lower()}:{iso_timestamp}".encode(
            "utf-8")

        payload_dict = {
            "credentials": [c.to_dict() for c in credentials],
            "totp_secret": user.get("totp_secret", ""),
            "password_hash": user.get("password_hash", ""),
            "private_key": private_pem,
            "public_key": user.get("public_key", ""),
        }
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        envelope_dict = {
            "format": "sentinelvault_backup",
            "version": 2,
            "username": username,
            "timestamp": iso_timestamp,
            "backup_salt": base64.b64encode(backup_salt).decode("ascii"),
            "envelope": encrypt_aead(payload_bytes, backup_key, aad),
            "public_key": user.get("public_key", ""),
        }
        return json.dumps(envelope_dict, indent=2).encode("utf-8")

    def restore_backup_envelope(
        self,
        blob: bytes,
        password: str,
        totp_code: Optional[str] = None,
        is_in_session: bool = False,
        current_username: Optional[str] = None,
    ) -> dict:
        """
        Restore backup envelope with strict authentication and overwrite prevention.
        1. Verifies AEAD tag against derived backup key and bound AAD.
        2. In-session restore: verifies target matches logged-in user.
        3. Disaster recovery (unauthenticated): requires valid TOTP code and REFUSES to overwrite existing accounts.
        """
        if len(blob) > MAX_BACKUP_SIZE_BYTES:
            raise StoreSecurityError(
                "Backup file exceeds maximum allowed size (5 MB).")

        try:
            data = json.loads(blob.decode("utf-8"))
        except Exception as exc:
            raise StoreSecurityError(
                "Invalid backup format: file is not valid JSON.") from exc

        if not isinstance(data, dict):
            raise StoreSecurityError("Malformed backup format.")

        if data.get("format") != "sentinelvault_backup" or data.get("version") != 2:
            raise StoreSecurityError(
                "Unsupported backup format or version mismatch.")

        username = validate_username(data.get("username", ""))
        timestamp = data.get("timestamp", "")
        backup_salt_str = data.get("backup_salt")
        envelope = data.get("envelope")

        if not backup_salt_str or not envelope or not timestamp:
            raise StoreSecurityError(
                "Malformed backup envelope: missing required fields.")

        backup_salt = base64.b64decode(backup_salt_str)
        backup_key = derive_backup_key(password, backup_salt)
        aad = f"sentinelvault:backup:v2:{username.lower()}:{timestamp}".encode(
            "utf-8")

        # Decrypt envelope with AEAD; tag verification proves possession of password and envelope integrity
        try:
            plaintext = decrypt_aead(envelope, backup_key, aad)
        except AuthenticationFailedError as exc:
            raise AuthenticationFailedError(
                "Failed to authenticate backup! Incorrect password or modified envelope.") from exc

        payload = json.loads(plaintext.decode("utf-8"))

        if is_in_session:
            if not current_username or current_username.lower() != username.lower():
                raise StoreSecurityError(
                    f"Backup belongs to user '{username}', cannot restore into active user '{current_username}'."
                )
            target_user = self.load_user(username)
            if not target_user:
                raise StoreSecurityError(
                    "Active user account not found on disk.")

            creds = [Credential.from_dict(d)
                     for d in payload.get("credentials", [])]
            salt = base64.b64decode(target_user["vault_salt"])
            vault_key = derive_vault_key(password, salt)
            self.write_credentials(target_user, vault_key, creds)
            self.save_user(username, target_user)
            return target_user

        # Disaster recovery path (unauthenticated)
        # CRITICAL SECURITY CHECK: Never overwrite an existing user account without active authentication!
        if self.user_path(username).exists():
            raise StoreSecurityError(
                f"Account '{username}' already exists on this machine. "
                "Disaster recovery cannot overwrite an existing account. Please log in first."
            )

        # Must verify TOTP code before creating restored account on disk
        totp_secret = payload.get("totp_secret", "")
        if not totp_code or not verify_code(totp_secret, totp_code):
            raise AuthenticationFailedError(
                "Invalid or missing TOTP code. Both password and 2FA are required for recovery.")

        # Re-create account with freshly derived keys
        private_pem = payload.get("private_key", "")
        public_pem = payload.get("public_key", "")
        password_hash = payload.get("password_hash", "")
        creds = [Credential.from_dict(d)
                 for d in payload.get("credentials", [])]

        restored_user = self.create_user(
            username=username,
            password=password,
            password_hash=password_hash,
            totp_secret=totp_secret,
            private_key=private_pem,
            public_key=public_pem,
        )
        salt = base64.b64decode(restored_user["vault_salt"])
        vault_key = derive_vault_key(password, salt)
        self.write_credentials(restored_user, vault_key, creds)
        self.save_user(username, restored_user)
        return restored_user
