# SentinelVault

### Defense-in-Depth Local Password Vault | CSE 4174 Cyber Security Lab

SentinelVault is a local Streamlit password manager that combines password authentication, TOTP two-factor authentication, authenticated encryption, covert backups, and signed hybrid sharing. The implementation is intentionally documented as it exists today, including residual risks and controls that are implemented in the library but not yet enforced by every UI path.

Read the background and security decisions in [context.md](context.md). Follow the runtime phases and file ownership in [workflow.md](workflow.md).

## Quickstart

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

The app opens at `http://localhost:8501`.

Run the automated suite:

```powershell
.\.venv\Scripts\pytest.exe -v
```

The current suite contains 36 unit, integration, and negative security tests.

## What Is Implemented

| Layer                   | Implementation                                                                                                                   | Main files                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Password authentication | bcrypt hashing and verification with work factor 12                                                                              | `auth/hashing.py`, `ui/login_page.py`                     |
| TOTP second factor      | RFC 6238, strict six-digit input, replay prevention, five failures leading to a 60-second lockout                                | `auth/totp.py`, `auth/session.py`                         |
| Vault encryption        | AES-256-GCM with 12-byte random nonces, 128-bit tags, AAD, and PBKDF2-HMAC-SHA256 at 600,000 iterations                          | `vault/crypto.py`, `vault/store.py`                       |
| Key separation          | Independent PBKDF2 domains for vault, RSA private-key, and backup keys                                                           | `vault/crypto.py`                                         |
| Disk protection         | Version 2 JSON user records, username validation, atomic replacement, 0o700 directory and 0o600 file permissions where supported | `vault/store.py`                                          |
| Backup and restore      | Authenticated AES-GCM backup envelope, optional PNG concealment, in-session identity check, and authenticated disaster recovery  | `vault/store.py`, `ui/backup_page.py`, `ui/login_page.py` |
| Steganography           | PNG-only RGB LSB embedding, explicit magic/length header, 5 MB payload cap, and 10,000,000-pixel Pillow limit                    | `stego/embed.py`, `stego/extract.py`                      |
| Secure sharing          | AES-GCM payload, RSA-2048 OAEP-SHA256 key wrapping, RSA-PSS-SHA256 signature, version 2 JSON package, and optional stego PNG     | `sharing/pgp_exchange.py`                                 |
| Public-key identity     | `SHA256:XX:XX:...` fingerprints and a persistent trusted-contact store                                                           | `sharing/keys.py`                                         |
| Session protection      | Inactivity auto-lock after 5 minutes and centralized sensitive-state cleanup                                                     | `app.py`, `auth/session.py`                               |

## Security Boundaries

### Authentication

Registration creates a bcrypt password hash, a TOTP secret, an RSA-2048 keypair, and an encrypted empty vault. The TOTP QR code and Base32 secret are displayed only during the registration ceremony. The user must confirm that the secret was saved before leaving enrollment.

Login is sequential:

1. The username and master password are checked against the stored bcrypt hash.
2. A derived vault key is held temporarily while the user enters a six-digit authenticator code.
3. The TOTP code is checked with replay prevention.
4. Only after both factors pass is the vault opened.

Password and OTP failures share the same process-local rate limiter. Five failures trigger a 60-second lockout. The session auto-locks after five minutes of inactivity.

### Authenticated encryption

`vault/crypto.py` uses AES-256-GCM. Each encrypted object contains an algorithm marker, a fresh 12-byte nonce, and base64 ciphertext with its authentication tag. AAD binds vault data to `sentinelvault:vault:v2:<username>`. Private keys use `sentinelvault:private_key:v2:<username>`. Backup envelopes bind the username and timestamp.

A stolen user JSON file therefore does not expose credential plaintext, and changing ciphertext or its bound metadata causes authentication failure. The private RSA key is encrypted independently from the vault data.

### Backup and recovery

A backup envelope contains the credentials and account material needed to rebuild an account, but the payload is protected by a backup-specific PBKDF2-derived key and AES-GCM. It can be downloaded as JSON or concealed in a PNG.

- In-session restore requires the active user, matching backup identity, and master password.
- Disaster recovery requires the master password and current TOTP code.
- Disaster recovery refuses to overwrite an existing account.
- A backup is not trusted merely because it is hidden inside an image; AEAD verification remains authoritative.

### Sharing

The sharing flow creates a hybrid package:

1. Generate a random AES-256 session key and 12-byte nonce.
2. Encrypt the payload with AES-256-GCM.
3. Encrypt the session key to the recipient's RSA public key with OAEP-SHA256.
4. Sign the versioned encrypted material with the sender's RSA-PSS-SHA256 private key.
5. Let the recipient verify the sender signature and decrypt with the matching private key.

`TrustedKeyStore` can pin a contact's public key fingerprint and detect substitution. The current UI displays the fingerprint and supports the store API, but does not yet block an import when a contact has no pin or a pin differs. See [context.md](context.md) for this explicit residual limitation.

### Steganographic concealment

The stego implementation embeds bytes into RGB PNG LSBs using a SentinelVault magic header and four-byte payload length. It validates PNG format, rejects malformed lengths, caps payloads at 5 MB, and limits Pillow image pixels. Steganography provides concealment only. The backup or PGP layers must still authenticate and decrypt the extracted bytes.

## User Experience Flow

### 1. Create a vault

Open **Create New Vault**, enter a username and master password twice, and initialize the vault. The app creates the encrypted user record and generates the TOTP enrollment QR code and secret. Scan or copy the secret into an external authenticator, then select **I have safely stored my TOTP secret**. The secret is no longer rendered by the application after confirmation.

### 2. Unlock the vault

Open **Unlock Vault**. Enter the username and master password, then continue to the second-factor screen. Enter the current six-digit authenticator code. A wrong password or OTP is denied and counted toward the shared five-attempt lockout. A successful second factor opens the dashboard.

### 3. Manage credentials

On **Vault Dashboard**, add a site, username, password, and optional notes. The password generator uses `secrets`, guarantees selected character classes, and shows an entropy-based strength estimate. Credentials are decrypted only for the active operation and are re-encrypted with fresh AES-GCM ciphertext when saved, edited, or deleted. Passwords are masked by default in the list.

### 4. Export a backup

Open **Stego Backups**, re-enter the master password, and optionally upload or generate a PNG cover. The app creates an authenticated backup envelope. If the image has enough capacity, the envelope is embedded into a downloadable PNG; otherwise, an authenticated JSON envelope is offered.

### 5. Restore a backup

For an active account, upload a JSON envelope or stego PNG in the in-session restore tab and re-enter the master password. The backup username must match the signed-in user. For a wiped account, use **Disaster Recovery** and supply both the master password and current TOTP code. Existing accounts cannot be overwritten through this path.

### 6. Share credentials

Open **PGP Secure Sharing**, select credentials, provide the recipient public key, and authorize signing with the sender master password. Download either the JSON package or a concealed PNG package. The recipient uploads it, provides the sender public key, and authorizes decryption with their master password. After signature and AEAD verification, the credentials appear as a masked preview and can be merged or discarded.

### 7. Lock and timeout

Use **Lock Vault & Logout** to clear authentication state, derived keys, pending credentials, sensitive widget values, and temporary imports. The same cleanup runs after five minutes without activity.

## Threat Model and Limits

The controls target local file theft, ciphertext tampering, password guessing, OTP replay, OTP brute force, backup forgery, account overwrite, malformed images, unauthorized RSA decryption, signature tampering, and public-key substitution.

This is a course project, not a production password manager. The operating system must protect the local `.sentinelvault` directory. The process-local limiter is not suitable for a multi-process server. Python and Streamlit cannot guarantee immediate memory zeroization of immutable strings. Some widget values exist transiently until their action or cleanup path runs. Fingerprint pinning is implemented and tested as a library, but UI enforcement remains follow-up work.

## Repository Map

```text
SentinelVault/
├── app.py                         Streamlit shell, routing, timeout, logout
├── context.md                     Problem statement and security decisions
├── workflow.md                    Phase-by-phase implementation map
├── auth/
│   ├── hashing.py                 bcrypt password hashing
│   ├── session.py                 rate limiting and session cleanup
│   └── totp.py                    enrollment, QR, validation, replay helper
├── vault/
│   ├── crypto.py                  AES-GCM, PBKDF2 domains, password tools
│   ├── models.py                  Credential dataclass
│   └── store.py                   encrypted user records and backups
├── sharing/
│   ├── keys.py                    RSA keys, fingerprints, trusted contacts
│   └── pgp_exchange.py             hybrid encrypted signed packages
├── stego/
│   ├── embed.py                   PNG LSB embedding and limits
│   └── extract.py                 PNG LSB extraction and validation
├── ui/
│   ├── login_page.py              registration, sequential login, recovery
│   ├── dashboard_page.py           credential CRUD and password generator
│   ├── backup_page.py              authenticated export and restore
│   └── share_page.py               package export, verification, and merge
└── tests/                         positive, negative, and end-to-end tests
```

## Verification

The complete suite covers cryptographic round trips, AAD tampering, nonce freshness, TOTP replay, lockout, session cleanup, inactivity timeout, path traversal, backup overwrite prevention, image limits, PGP tampering, key substitution, stego transport, and the complete registration-to-sharing flow.

```powershell
.\.venv\Scripts\pytest.exe -v
```

Current baseline: 36 passed.
