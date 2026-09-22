# SentinelVault Implementation Workflow

This document is the executable phase map for SentinelVault. It connects the user journey in [README.md](README.md) to the design rationale in [context.md](context.md) and to the modules that implement each phase.

## Phase 0: Environment and Application Shell

**User-visible result:** The local Streamlit application starts and routes between authentication, dashboard, backup, sharing, and architecture views.

**Implemented in:**

- `requirements.txt`: Streamlit, bcrypt, pyotp, cryptography, Pillow, QR generation, and pytest.
- `app.py`: page configuration, `VaultStore` creation, authentication gate, sidebar navigation, logout, and architecture view.
- `auth/session.py`: five-minute inactivity check and centralized cleanup.

**Security checkpoint:** The application does not render authenticated pages until `st.session_state.authenticated` is true. Logout calls `cleanup_session_state()` before rerunning the app.

## Phase 1: Registration and Identity Creation

**User-visible result:** A new user receives a protected vault and a one-time TOTP enrollment ceremony.

**Implemented in:**

- `ui/login_page.py`: registration form, password confirmation, minimum password length check, QR display, Base32 secret display, and one-time enrollment acknowledgment.
- `auth/hashing.py`: bcrypt hash generation and verification.
- `auth/totp.py`: random secret, `otpauth://` URI, and QR image generation.
- `sharing/keys.py`: RSA-2048 private/public keypair generation.
- `vault/store.py:create_user()`: username validation, salt generation, v2 record creation, encrypted empty vault, and encrypted private key.
- `vault/crypto.py`: vault and private-key domain-separated key derivation plus AES-GCM encryption.

**Stored record:** The user JSON contains the username, bcrypt hash, TOTP secret, vault salt, encrypted vault, encrypted RSA private key, and public key. The master password and private PEM are not stored as plaintext fields.

**Security checkpoint:** The TOTP secret is rendered only while `new_registration` exists. Selecting the enrollment acknowledgment removes it from Streamlit state.

## Phase 2: Sequential Two-Factor Login

**User-visible result:** The user passes a password gate first and an authenticator-code gate second.

**Implemented in:**

- `ui/login_page.py`: password stage, temporary derived vault key, OTP stage, lockout messages, and successful session initialization.
- `auth/session.py:verify_master_password()`: bcrypt verification.
- `auth/session.py:verify_totp()`: replay-aware TOTP verification.
- `auth/session.py:CentralizedRateLimiter`: shared failure counter, lockout timer, and last accepted TOTP timestep.
- `auth/totp.py:verify_code_with_replay_prevention()`: strict six-digit validation and same-step replay rejection.

**Session transition:** Password verification derives `temp_vault_key`. After successful TOTP verification, that value becomes `vault_key`; pending login fields and the OTP widget are removed. The plaintext master password is not promoted to persistent session state.

**Security checkpoint:** Password and OTP failures both call `record_failed_attempt()`. The fifth failure locks the username for 60 seconds.

## Phase 3: Vault CRUD and Password Generation

**User-visible result:** Authenticated users can add, find, edit, delete, and mask credentials.

**Implemented in:**

- `ui/dashboard_page.py`: dashboard, masked password view, search, CRUD forms, reauthentication-free in-session operations, and transient widget cleanup after save.
- `vault/models.py:Credential`: credential schema, IDs, timestamps, serialization, and update behavior.
- `vault/crypto.py:generate_password()`: cryptographically secure password generation.
- `vault/crypto.py:evaluate_password_strength()`: entropy estimate, score, label, and feedback.
- `vault/store.py:read_credentials()`: AES-GCM decryption with username AAD.
- `vault/store.py:write_credentials()`: JSON serialization and fresh AES-GCM encryption.

**Security checkpoint:** Credential plaintext is absent from the persisted user record. A ciphertext or username/AAD change fails GCM verification. Passwords are masked in the normal list view.

## Phase 4: Authenticated Backup Export

**User-visible result:** An authenticated JSON backup or optional concealed PNG backup can be downloaded.

**Implemented in:**

- `ui/backup_page.py`: master-password reauthentication, cover upload/sample generation, capacity decision, download buttons, and error handling.
- `vault/store.py:create_backup_envelope()`: in-memory credential/private-key extraction, backup-specific salt and key, timestamp-bound AAD, and version 2 envelope.
- `vault/crypto.py:derive_backup_key()` and `encrypt_aead()`: backup confidentiality and integrity.
- `stego/embed.py`: optional PNG concealment.

**Security checkpoint:** Export requires the master password again. The backup envelope is authenticated before it can be used, and stego is treated as concealment rather than proof of authenticity.

## Phase 5: Restore and Disaster Recovery

**User-visible result:** A user can restore an active vault or rebuild a missing account without allowing an uploaded backup to overwrite an existing account.

**Implemented in:**

- `ui/backup_page.py`: in-session restore from JSON or PNG.
- `ui/login_page.py`: disaster recovery from JSON or PNG with password and TOTP fields.
- `stego/extract.py`: extraction, PNG validation, magic header validation, payload length checks, and image limits.
- `vault/store.py:restore_backup_envelope()`: format/version validation, backup AEAD verification, active-username binding, existing-account refusal, TOTP verification for disaster recovery, and account recreation.

**Restore rules:**

- Active-session restore requires a matching username and password-authenticated backup.
- Missing-account recovery requires both password and current TOTP.
- Existing account files are never overwritten by unauthenticated recovery.

**Security checkpoint:** Tampering with the envelope, timestamp, username, ciphertext, or supplied credentials prevents restoration.

## Phase 6: Secure Sharing Package

**User-visible result:** Selected credentials can be shared as a JSON package or a stego PNG with confidentiality and sender authentication.

**Implemented in:**

- `ui/share_page.py`: credential selection, recipient/sender key fields, master-password authorization, package download, import, masked preview, merge, and discard.
- `vault/store.py:private_key()`: independent private-key decryption using the sender/recipient master password.
- `sharing/pgp_exchange.py:create_package()`: ephemeral AES-256 key, AES-GCM payload, RSA-OAEP key wrapping, and RSA-PSS signature.
- `sharing/pgp_exchange.py:open_package()`: signature verification, RSA private-key unwrap, and AES-GCM authentication.
- `sharing/pgp_exchange.py:create_stego_share_package()` and `open_stego_share_package()`: optional PNG transport.

**Package binding:** The package uses the `sentinelvault_pgp_v2` AAD and signs the version marker, encrypted session key, nonce, and ciphertext. A modified payload or wrong sender key fails before credentials are accepted.

## Phase 7: Fingerprint Trust

**User-visible result:** Public keys have a stable display identity and a local trust record.

**Implemented in:**

- `sharing/keys.py:get_key_fingerprint()`: SHA-256 fingerprint formatted as `SHA256:XX:XX:...`.
- `sharing/keys.py:TrustedKeyStore`: local contact records, pinning, and substitution detection.
- `ui/share_page.py`: fingerprint display for local and recipient keys.
- `tests/test_sharing.py`: pinning and substitution tests.

**Current boundary:** The store and tests enforce fingerprint comparison when called. The current UI does not automatically require a pre-pinned contact or block every unpinned key. Full UI enforcement is a follow-up phase.

## Phase 8: Session Cleanup and Auto-Lock

**User-visible result:** Explicit logout and five minutes of inactivity return the app to the unauthenticated screen.

**Implemented in:**

- `app.py`: timeout check before authenticated routing and logout button.
- `auth/session.py:cleanup_session_state()`: removal of passwords, derived keys, pending registration, imported credentials, file bytes, and known widget keys; dynamic edit/toggle keys are also removed.
- `auth/session.py:check_inactivity_timeout()`: five-minute timeout and cleanup trigger.

**Security checkpoint:** Cleanup tests verify that sensitive keys and representative plaintext values are removed from the state mapping. Python immutable strings cannot be guaranteed to be zeroized at the allocator level.

## Phase 9: Verification and Regression Evidence

**Implemented in:**

- `tests/test_crypto.py`: AES-GCM behavior, domain separation, AAD tampering, nonce freshness, and password tooling.
- `tests/test_auth.py`: bcrypt, TOTP, replay defense, lockout, cleanup, and inactivity timeout.
- `tests/test_stego.py`: PNG LSB round trips, invalid images, capacities, and payload limits.
- `tests/test_sharing.py`: hybrid package round trips, signature failures, wrong recipients, stego transport, and fingerprint pinning.
- `tests/test_security_hardening.py`: negative tampering, AAD substitution, backup overwrite, path traversal, oversized payload, and session-state cases.
- `tests/test_e2e_vault.py`: registration, failed OTP, successful login, encrypted disk check, backup recovery, and Alice-to-Bob sharing.

Run:

```powershell
.\.venv\Scripts\pytest.exe -v
```

Current result: 36 tests pass.

## End-to-End Summary

```text
Register
  -> bcrypt hash + TOTP enrollment + RSA keypair + encrypted empty vault
Unlock
  -> password check -> temporary derived key -> replay-aware OTP -> authenticated session
Use vault
  -> decrypt with AES-GCM/AAD -> CRUD -> re-encrypt on save
Backup
  -> reauthenticate -> authenticated v2 envelope -> optional PNG concealment
Recover
  -> extract -> verify AEAD -> require identity/password/TOTP rules -> restore without overwrite
Share
  -> select credentials -> AES-GCM + RSA-OAEP + RSA-PSS -> recipient verifies/decrypts -> merge or discard
Lock
  -> clear session values and keys -> return to login
```
