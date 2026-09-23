# Technical Implementation Workflow

This document maps the frontend actions to the backend operation, security operation, and result.

## 1. Application Startup

`app.py` configures Streamlit, creates `VaultStore`, initializes authentication state, checks the five-minute timeout, and routes authenticated users through the sidebar to **📋 Vault Dashboard**, **🖼️ Stego Backups**, **🤝 PGP Secure Sharing**, or **📖 Security Architecture**.

## 2. Registration

In **✨ Create New Vault**, `ui/login_page.py` validates the username and password confirmation. `auth/hashing.py` creates the bcrypt verifier; `auth/totp.py` creates the TOTP secret and QR code; `sharing/keys.py` creates an RSA-2048 keypair. `VaultStore.create_user()` derives keys and writes an empty AES-256-GCM vault plus encrypted private key to the local JSON store.

The user confirms **✅ I have safely stored my TOTP secret**. The enrollment data is then removed from session state.

## 3. Login and TOTP

In **🔑 Unlock Vault**, the user enters **Username** and **Master Password**, then selects **Continue to Second Factor ➡️**. bcrypt verifies the password. The app derives a temporary vault key and shows **6-digit Authenticator Code**. **Unlock Vault 🔓** invokes replay-aware TOTP verification. Password and TOTP failures use the shared `CentralizedRateLimiter`; five failures lock the username for 60 seconds.

## 4. Vault Unlock

After both factors pass, the temporary derived key becomes `vault_key` in session state. The dashboard calls `VaultStore.read_credentials()`, derives the username-bound AAD, and decrypts the vault with AES-GCM. Credential plaintext is held for the active UI operation.

## 5. Add a Credential

On **🔐 Vault Dashboard**, open **➕ Add New Credential**. Enter **Service / Website URL**, **Username or Email**, **Password**, and optional **Notes (Optional)**. The **🎲 Generate Secure Password** popover supports **Generate Now** and **Use Generated Password**. **Encrypt & Store Credential 💾** serializes the `Credential`, encrypts the full list with a fresh AES-GCM nonce, and saves the user record.

## 6. View, Search, Edit, and Delete

**📋 Saved Credentials** displays site, username, notes, and a masked password. **Show Password** reveals a password in the current view. **🔍 Search credentials by site or username** filters the list. **✏️ Edit** opens fields for **Site**, **Username**, **Password**, and **Notes**; **Save Changes** updates the timestamp and re-encrypts the list. **🗑️ Delete** removes the entry and persists a newly encrypted list.

## 7. Vault Encryption and Decryption

`vault/crypto.py` uses PBKDF2-HMAC-SHA256 with 600,000 iterations and domain-separated salts. `encrypt_aead()` uses AES-256-GCM, a fresh 12-byte nonce, and AAD. `VaultStore.read_credentials()` verifies the authentication tag before parsing JSON; `write_credentials()` encrypts the serialized credentials again after every mutation.

## 8. Storage Preview

At the bottom of the dashboard, expand **🛡️ Vault Security Details & Storage Preview (Safe Metadata)**. The UI calls `VaultStore.get_safe_storage_preview()` and displays the persisted JSON metadata and ciphertext without displaying credential plaintext. The panel identifies AES-GCM, the tag, nonce, PBKDF2, domain separation, and username-bound AAD.

## 9. Standard Backup

Open **🖼️ Stego Backups**, choose **📦 Create Backup (Normal & Stego)**, enter **Confirm Master Password**, select **Standard Authenticated Backup (.json) — Cryptographic AEAD Envelope**, and press **Generate Backup 🔒**. `create_backup_envelope()` creates a version 2 AES-GCM envelope with backup-specific PBKDF2 derivation, random salt, and timestamp-bound AAD. Use **⬇️ Download Authenticated Backup Envelope (.json)**.

## 10. Steganographic Backup

Select **Covert Steganographic Backup (.png) — Concealed in Image Pixels**. Use **Generate Sample PNG Carrier 🎨** or upload a PNG with **Upload custom PNG carrier (Optional)**. The encrypted envelope is embedded with RGB LSBs by `stego/embed.py`; use **⬇️ Download Stego Backup (PNG)**. The image hides the payload but does not replace AES-GCM authentication.

## 11. Normal Restore

In **📥 Restore Vault Backup**, upload **Backup File (.json or stego .png)**, enter **Master Password**, and press **Authenticate and Restore 🔄**. The store verifies the version, username, timestamp, derived backup key, AAD, and GCM tag. An active restore must match the logged-in username. The optional **🧪 Demonstrate Security Failure: Simulate Tampered Backup File (Bit-Flipping Attack)** corrupts the envelope and should produce an AEAD failure.

## 12. Disaster Recovery

On the login screen, open **🔄 Disaster Recovery**. Upload **SentinelVault Backup (.json or stego .png)**, enter **Master Password** and **Current 6-digit TOTP Code**, then press **Authenticate and Restore Account**. `VaultStore.restore_backup_envelope()` requires both factors and refuses to overwrite an existing account. **🧪 Demonstrate Security Failure: Simulate Tampered Backup File** demonstrates rejection before restoration.

## 13. Secure Sharing: Sender

Open **🤝 PGP Secure Sharing** and use **📤 Export Shared Package**. Select credentials, choose a recipient through **From Trusted Contacts / Local Users** or **Manual PEM Input**, inspect **Recipient Key Fingerprint**, enter **Master Password**, and choose **Standard JSON Security Package (.json)** or **Covert Steganographic PNG (.png)**. Press **Generate Encrypted & Signed Package 🔐**. `create_package()` encrypts with AES-GCM, wraps the session key with RSA-OAEP, and signs package material with RSA-PSS.

## 14. Secure Sharing: Recipient

Use **📥 Verify & Import Package**. Upload **package file (.json or stego .png)**, enter **Claimed Sender Username**, provide **Sender RSA Public Key (for PSS signature verification)**, enter **Master Password**, and press **Verify Signature & Decrypt 🔍**. The recipient sees a masked authenticated preview. **Merge into My Vault 📥** adds only new site/username pairs; the package can otherwise be discarded by leaving it unmerged.

## 15. Trusted Contacts and Fingerprints

Use **🔏 Trusted Contacts (Fingerprint Store)** to inspect contacts and **My Public Identity**. Add a contact with **Pin a New Trusted Contact**, **Contact Name / Username**, **Contact RSA Public Key (PEM)**, and **Pin & Trust Contact Key 📌**; remove one with **Unpin 🗑️**. During import, select **Quick-fill sender key from Contacts / Local Users:** or paste a key. For an unpinned sender, the UI displays a warning and offers **Pin & Trust Key for '<name>' 🔏**. For a pinned contact, `TrustedKeyStore.verify_trust()` compares the calculated SHA-256 fingerprint and blocks the import if substitution is detected.

## 16. Tamper and Security Demonstrations

The restore pages provide tampered-backup simulation checkboxes. The sharing import page provides **🧪 Demonstrate Security Failure: Simulate Tampered Package (Corrupt Signature / Ciphertext)**. A corrupted backup fails AES-GCM authentication; a modified sharing signature fails RSA-PSS verification. The dashboard storage preview demonstrates that persisted credential data is ciphertext.

## 17. Logout, Timeout, and Cleanup

Use **🔒 Lock Vault & Logout** in the sidebar to call `cleanup_session_state()` and return to the login screen. `check_inactivity_timeout()` performs the same cleanup after five minutes. The cleanup removes derived keys, authentication state, pending values, imported credentials, and dynamic credential widget state.

## Module Map

```text
app.py                         startup, routing, timeout, logout
ui/login_page.py               registration, login, disaster recovery
ui/dashboard_page.py           credential CRUD and storage preview
ui/backup_page.py              backup creation and active restore
ui/share_page.py               package export/import and trusted-key UI
auth/hashing.py                bcrypt
auth/session.py                rate limiting and session cleanup
auth/totp.py                   TOTP and replay prevention
vault/crypto.py                PBKDF2, AES-GCM, password tools
vault/store.py                 encrypted records and backup envelopes
sharing/keys.py                RSA keys, fingerprints, TrustedKeyStore
sharing/pgp_exchange.py        hybrid packages and package stego transport
stego/embed.py, extract.py     PNG LSB concealment
```
