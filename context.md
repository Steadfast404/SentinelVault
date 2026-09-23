# Security Context and Design Rationale

## Problem

A password vault concentrates valuable credentials in one place. SentinelVault demonstrates how layered authentication, authenticated encryption, protected recovery, and authenticated sharing reduce the impact of password guessing, local file theft, tampering, and impersonation.

## Threat Model

The project considers an attacker who can guess passwords, observe or modify stored ciphertext, submit malformed or forged backups, tamper with a sharing package, or substitute a public key. It does not claim to protect a compromised operating system, an already-unlocked process, or a multi-process server deployment.

## Design Decisions

### bcrypt

Master passwords are verified with bcrypt rather than stored directly. Its intentionally expensive password hashing makes offline guessing of the stored verifier more costly.

### TOTP

TOTP adds possession of an authenticator to the password requirement. Login accepts a strict six-digit code, rejects reuse within the same 30-second timestep, and allows a small clock-drift window.

### PBKDF2-HMAC-SHA256

The master password and random 16-byte salt derive 256-bit keys with PBKDF2-HMAC-SHA256 using 600,000 iterations. The work factor slows password guessing while the salt prevents identical passwords from producing identical derived keys across accounts.

### AES-256-GCM

AES-GCM provides confidentiality and authenticated integrity in one operation. It is used for the credential vault, the RSA private key, and authenticated backup envelopes.

Each encryption uses a fresh 12-byte nonce. GCM appends an authentication tag; changing ciphertext or authenticated metadata causes decryption to fail. Additional Authenticated Data (AAD) binds the ciphertext to its purpose and account, such as `sentinelvault:vault:v2:<username>`.

### Domain-separated keys

The vault, private-key, and backup keys use different PBKDF2 domains. A derived key for one purpose is therefore not reused for another purpose. The backup also receives its own random salt and timestamp-bound AAD.

## Backup and Recovery

Backup creation requires the master password again. `VaultStore.create_backup_envelope()` decrypts the required values in memory, packages credentials and account material, and protects the payload with a backup-specific PBKDF2 key and AES-GCM.

An active-session restore requires a matching username and password-authenticated envelope. Disaster recovery requires the password and current TOTP code, and refuses to overwrite an existing account. A modified username, timestamp, ciphertext, password, or TOTP value prevents successful recovery.

## Steganography Is Concealment

PNG LSB steganography hides an already encrypted payload inside RGB pixel least-significant bits. It does not provide encryption or authenticity. The backup's AES-GCM authentication remains the security boundary, while the image carrier only reduces obvious visibility of the file's purpose.

## Secure Sharing Architecture

Sharing is a hybrid construction:

1. Selected credentials are encrypted with an ephemeral AES-256-GCM session key.
2. RSA-OAEP with SHA-256 encrypts that session key to the recipient's RSA-2048 public key.
3. RSA-PSS with SHA-256 signs the encrypted session key, nonce, and ciphertext using the sender's private key.
4. The recipient verifies the signature before RSA-OAEP unwrapping and AES-GCM decryption.

The package uses fixed AAD `sentinelvault_pgp_v2`. A changed package fails signature verification or AEAD authentication.

## Public-Key Fingerprints and Trusted Contacts

The application calculates a SHA-256 digest of the public-key PEM and displays it as `SHA256:XX:XX:...`. `TrustedKeyStore` persists a contact name, public key, and fingerprint in the local store. Pinning a key creates an identity reference; later `verify_trust()` compares the received key's fingerprint with the pinned value and detects substitution. The UI warns for untrusted keys and checks pinned contacts during relevant sharing verification, but a user may still choose manual input for an unpinned key.

## Session Security

The application keeps a derived vault key in Streamlit session state after the password and TOTP stages succeed; it does not promote the plaintext master password to persistent session state. Five minutes without activity triggers cleanup. **🔒 Lock Vault & Logout** invokes the same cleanup, which removes authentication state, derived keys, pending values, imported credentials, and dynamic widget state.

Password and TOTP failures share a process-local counter. Five failures lock the username for 60 seconds.

## Scope and Genuine Limitations

- The local JSON store still contains password hashes, the TOTP enrollment secret, public metadata, and encrypted material; operating-system access control remains important.
- Python and Streamlit cannot guarantee allocator-level zeroization of immutable strings.
- The rate limiter is process-local and does not provide distributed server protection.
- Steganography can be detected by a capable analyst and does not replace encryption.
- Trusted-key checks are available through `TrustedKeyStore` and the sharing UI, but manual unpinned-key workflows remain possible.
- This implementation is a short educational lab project rather than a production password manager.
