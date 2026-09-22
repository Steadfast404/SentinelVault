# SentinelVault Context and Security Decisions

[README.md](README.md) is the implementation and usage guide. [workflow.md](workflow.md) maps each runtime phase to its owning modules and functions. This document records the problem that shaped SentinelVault, the architecture decisions made during hardening, and the remaining boundaries that should not be overstated.

## 1. Problem Faced

A password vault is a high-value single point of failure. An unprotected JSON file exposes every credential; a password-only login is vulnerable when the master password is guessed or stolen; a backup can become an unauthenticated account replacement mechanism; and a sharing feature can leak data or accept a substituted public key.

The initial project specification and early implementation also diverged from the security model being demonstrated:

- `context.md` described AES-CBC, while the hardened implementation uses AES-256-GCM.
- The original design treated steganography as protection, although LSB steganography only conceals the existence of a payload.
- Early recovery semantics could be read as allowing an uploaded backup to replace an account without proving ownership.
- The UI design needed to avoid rendering TOTP helpers and retaining master passwords in Streamlit state.
- Sharing required a verifiable sender identity, not only encryption to a recipient.
- Security claims needed to be tied to executable negative tests rather than only prose.

The current code addresses the primary risks with authenticated encryption, versioned metadata, authenticated recovery, centralized lockout, replay prevention, size limits, and test coverage.

## 2. Current Security Model

SentinelVault is a local Streamlit password vault with five cooperating layers:

| Layer              | Current implementation                                                                                                                       | Security purpose                                                                                 |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Authentication     | bcrypt password hash with work factor 12 in `auth/hashing.py`                                                                                | Makes stored password verification data expensive to crack and never stores the master password. |
| Second factor      | RFC 6238 TOTP, strict six-digit validation, replay prevention, and five-failure/60-second lockout in `auth/totp.py` and `auth/session.py`    | Requires the authenticator code after password verification and prevents same-step reuse.        |
| At-rest encryption | AES-256-GCM with 12-byte nonces, 128-bit tags, PBKDF2-HMAC-SHA256 with 600,000 iterations, and domain-separated keys in `vault/crypto.py`    | Detects tampering and keeps credentials unreadable without the derived key.                      |
| Covert backup      | PNG-only RGB LSB embedding with a magic header, explicit payload length, 5 MB limit, and Pillow pixel limits in `stego/`                     | Conceals an already authenticated backup; it is not the confidentiality boundary.                |
| Secure sharing     | RSA-2048 OAEP-SHA256 for an ephemeral AES key, AES-256-GCM for the payload, RSA-PSS-SHA256 signatures, and fingerprint storage in `sharing/` | Provides recipient confidentiality and sender authenticity/integrity.                            |

## 3. Hardening Decisions and Considered Updates

### 3.1 AES-CBC to AES-GCM

AES-CBC was rejected for the final design because encryption alone does not authenticate ciphertext or metadata. The final format uses `encrypt_aead()` and `decrypt_aead()` in `vault/crypto.py`. Each payload receives a fresh 96-bit nonce and an authentication tag. AAD binds the payload to its format and identity, for example `sentinelvault:vault:v2:<username>`.

Separate PBKDF2 domains derive vault, private-key, and backup keys. This prevents one derived key from being silently reused for unrelated purposes. The v2 format marker is stored with user, backup, and sharing containers so readers can reject unsupported formats.

### 3.2 Authenticated backups and recovery

Backups contain the credentials and account material needed for recovery, but the complete backup payload is encrypted and authenticated with a backup-specific key. The backup AAD includes the username and timestamp.

Recovery has two modes:

- In-session restore requires an authenticated session, the active username, and the backup password. A backup for another user is rejected.
- Disaster recovery authenticates the backup with the password, requires a valid TOTP code, and refuses to create a restored account if the target account already exists. This prevents an unauthenticated upload from overwriting an existing account.

### 3.3 Session and UI secret handling

The UI does not store the plaintext master password as a persistent session field. After password verification, it stores a derived vault key temporarily while the second factor is completed. Logout and inactivity timeout call `cleanup_session_state()` to remove authentication state, keys, pending values, widget buffers, generated passwords, imported credentials, and dynamic edit/toggle fields.

The TOTP QR code and Base32 secret are shown only in the registration ceremony, until the user acknowledges that the secret was saved. Login renders only an OTP input. The testing-only `get_current_code_for_testing()` helper remains in `auth/totp.py` for automated tests and is not imported by the production UI.

### 3.4 Centralized authentication controls

Password and OTP failures use the same process-wide, thread-safe `CentralizedRateLimiter`. Five consecutive failures trigger a 60-second lockout. A successful complete login clears failed attempts. Successful TOTP verification records the accepted timestep so the same code cannot be replayed during its validity window.

### 3.5 Sharing identity and trust

Each user receives an RSA-2048 keypair. The private PEM is encrypted at rest using a private-key-specific derived key and AES-GCM. A sharing package is version 2 and signs the encrypted session key, nonce, and ciphertext together.

`TrustedKeyStore` persists a contact's public key and standardized `SHA256:XX:XX:...` fingerprint. Its API and substitution tests are implemented. The current sharing page displays fingerprints and accepts public keys, but it does not yet require a pinned contact match before every import/export. That is a remaining UI integration task, not a claim made by this documentation.

### 3.6 Steganography as concealment

The stego layer accepts PNG only, limits images to 10,000,000 pixels, encodes a magic header and payload length, and caps payloads at 5 MB. It does not authenticate the payload itself. An extracted backup or sharing package must still pass its AES-GCM or signature verification step.

## 4. Current Residual Risks

The implementation is hardened for the course demonstration, but it is not a production password manager:

- The local JSON store contains password hashes, TOTP enrollment secrets, public metadata, and encrypted material; filesystem access must still be protected by the operating system.
- Some Streamlit widget values and the verified incoming credential preview exist transiently until their action, discard, logout, or timeout path removes them. Python cannot reliably zero immutable strings in memory.
- `TrustedKeyStore` is available and tested, but the sharing UI currently reports fingerprints rather than enforcing a pin automatically.
- The recovery payload includes account metadata inside an authenticated envelope; confidentiality depends on the master password and backup key derivation.
- The global rate limiter is process-local. A multi-process or network deployment would require shared rate-limit state and a different threat model.

These limitations are recorded so the demo can explain what each control guarantees without claiming that concealment, a local GUI, or a test helper provides stronger protection than it actually does.

## 5. Verification

The executable security evidence is in:

- [tests/test_crypto.py](tests/test_crypto.py): GCM round trips, nonce freshness, AAD tampering, and domain separation.
- [tests/test_auth.py](tests/test_auth.py): bcrypt, TOTP, replay prevention, lockout, cleanup, and inactivity timeout.
- [tests/test_security_hardening.py](tests/test_security_hardening.py): negative tamper, overwrite, path traversal, payload limit, substitution, and state cleanup tests.
- [tests/test_sharing.py](tests/test_sharing.py): hybrid package, signature, recipient, stego, and fingerprint trust tests.
- [tests/test_e2e_vault.py](tests/test_e2e_vault.py): registration through backup recovery and two-user sharing.

Run the full suite with:

```powershell
.\.venv\Scripts\pytest.exe -v
```

The current baseline is 36 passing tests.

## 6. Course Mapping

- Lab 3: bcrypt and TOTP two-factor authentication.
- Lab 4: password-based key derivation and authenticated symmetric encryption at rest.
- Lab 5: PNG LSB steganographic concealment and input validation.
- Lab 6: RSA hybrid sharing, digital signatures, and public-key identity.

The project contribution is the threat-model-driven composition of these techniques, plus the negative tests that demonstrate how tampering and misuse are rejected.
