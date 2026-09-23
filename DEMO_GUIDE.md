# SentinelVault Frontend Demonstration Guide

Use only fictional values such as `demo_user`, `DemoPassword2026!`, `github.example`, and `demo@example.com`. Do not use a real password, secret, private key, or personal account.

## 1. Start Application

**What to click:** Start the app with `streamlit run app.py`, then open the local Streamlit URL.

**What to enter:** Nothing.

**Expected result:** The **🛡️ SentinelVault** login screen appears with **🔑 Unlock Vault**, **✨ Create New Vault**, and **🔄 Disaster Recovery** tabs.

**Viva statement:** “The application is a local Streamlit client whose authenticated pages are gated by the session state.”

## 2. Register User

**What to click:** Open **✨ Create New Vault**. Enter a demo username, **Master Password**, and **Confirm Master Password**, then click **Initialize & Generate Keys 🛡️**.

**What to enter:** For example, `demo_user` and `DemoPassword2026!`.

**Expected result:** A QR code and **TOTP Secret (Base32)** appear. Scan or record the demo secret in an authenticator, then click **✅ I have safely stored my TOTP secret**.

**Security demonstrated:** bcrypt password hashing, TOTP enrollment, RSA-2048 key generation, and creation of an encrypted empty vault.

**Viva statement:** “Registration creates the identity material, but the master password is never stored as plaintext.”

## 3. Login with Password and TOTP

**What to click:** In **🔑 Unlock Vault**, enter the demo username and password, then click **Continue to Second Factor ➡️**. Enter the current six-digit code and click **Unlock Vault 🔓**.

**What to enter:** The demo credentials and the current code from the authenticator.

**Expected result:** **📋 Vault Dashboard** opens.

**Security demonstrated:** bcrypt verification, sequential TOTP verification, replay prevention, rate limiting, and temporary derived-key handling.

**Viva statement:** “A correct password alone does not unlock the vault; the second factor must also pass.”

## 4. Add a Demo Credential

**What to click:** Open **➕ Add New Credential**. Fill **Service / Website URL**, **Username or Email**, **Password**, and optionally **Notes (Optional)**. Click **Encrypt & Store Credential 💾**.

**What to enter:** `github.example`, `demo@example.com`, and `FakeGitHubPass!2026`.

**Expected result:** A success message appears and the entry is listed under **📋 Saved Credentials**.

**Security demonstrated:** The credential list is serialized, AES-256-GCM encrypted with a fresh nonce, and persisted as ciphertext.

**Viva statement:** “The UI handles plaintext only while the authenticated session is using it; the stored record contains encrypted data.”

## 5. View, Search, Edit, and Delete

**What to click:** Use **Show Password** to reveal the demo password. Search with **🔍 Search credentials by site or username**. Click **✏️ Edit**, change **Notes**, and click **Save Changes**. Later click **🗑️ Delete**.

**What to enter:** Search for `github`; change notes to `demo only`.

**Expected result:** Search filters the list, the edit updates the timestamp, and delete removes the entry after persistence.

**Security demonstrated:** Password masking, authenticated read/write operations, and fresh re-encryption after mutation.

**Viva statement:** “Every CRUD change rewrites the encrypted credential list rather than writing a plaintext credential file.”

## 6. Open Storage Preview

**What to click:** Expand **🛡️ Vault Security Details & Storage Preview (Safe Metadata)**.

**What to enter:** Nothing.

**Expected result:** A safe JSON preview shows encrypted record metadata and ciphertext. Credentials are not displayed in the preview.

**Security demonstrated:** AES-256-GCM, 12-byte nonces, authentication tags, PBKDF2-HMAC-SHA256, domain separation, and username-bound AAD.

**Viva statement:** “This is a demonstrable storage check: the disk record exposes metadata and ciphertext, not the credential plaintext.”

## 7. Create an Encrypted Backup

**What to click:** Select **🖼️ Stego Backups**, open **📦 Create Backup (Normal & Stego)**, enter **Confirm Master Password**, select **Standard Authenticated Backup (.json) — Cryptographic AEAD Envelope**, and click **Generate Backup 🔒**. Click **⬇️ Download Authenticated Backup Envelope (.json)**.

**What to enter:** The demo master password.

**Expected result:** A version 2 authenticated JSON backup becomes available.

**Security demonstrated:** Reauthentication, backup-specific PBKDF2 derivation, AES-GCM authentication, random salt, and timestamp-bound AAD.

**Viva statement:** “The backup is independently authenticated, so a modified file or wrong password is rejected.”

## 8. Demonstrate Tampered Backup Rejection

**What to click:** In **📥 Restore Vault Backup**, upload the demo JSON backup, enter **Master Password**, check **🧪 Demonstrate Security Failure: Simulate Tampered Backup File (Bit-Flipping Attack)**, and click **Authenticate and Restore 🔄**.

**What to enter:** The demo master password.

**Expected result:** The UI reports **Security Failure Detected: AEAD Authentication Failed!** and does not restore the file.

**Security demonstrated:** AES-GCM authentication tags detect ciphertext modification.

**Viva statement:** “The file can be parsed, but it cannot be trusted because the authentication tag no longer matches.”

## 9. Create and Extract a Steganographic Backup

**What to click:** Return to **📦 Create Backup (Normal & Stego)**, select **Covert Steganographic Backup (.png) — Concealed in Image Pixels**, click **Generate Sample PNG Carrier 🎨** if desired, then click **Generate Backup 🔒** and **⬇️ Download Stego Backup (PNG)**.

**What to enter:** The demo master password.

**Expected result:** A PNG preview and download appear. During restore, upload the PNG and the UI reports that the payload was extracted from carrier LSBs.

**Security demonstrated:** PNG-only RGB LSB concealment with a magic header and payload-length validation. The embedded payload remains AES-GCM protected.

**Viva statement:** “Steganography hides the existence of the backup; it is not the encryption layer.”

## 10. Demonstrate Normal or Disaster Recovery

**What to click:** For an active account, use **📥 Restore Vault Backup**, upload JSON or PNG, enter **Master Password**, and click **Authenticate and Restore 🔄**. For a missing account, use **🔄 Disaster Recovery**, upload **SentinelVault Backup (.json or stego .png)**, enter **Master Password** and **Current 6-digit TOTP Code**, then click **Authenticate and Restore Account**.

**What to enter:** The demo password and, for disaster recovery, the current demo TOTP code.

**Expected result:** Active restore updates the matching account. Disaster recovery rebuilds only a missing account; an existing account is not overwritten.

**Security demonstrated:** Username binding, authenticated backup verification, TOTP-protected disaster recovery, and overwrite prevention.

**Viva statement:** “Recovery has stricter rules than ordinary import because an uploaded backup must not replace an existing account without authentication.”

## 11. Secure Credential Sharing

**What to click:** Register a second demo user if needed. On **🤝 Secure Vault Sharing & Trusted Keys**, use **📤 Export Shared Package**, select credentials, choose **From Trusted Contacts / Local Users** or **Manual PEM Input**, choose a package format, enter **Master Password**, and click **Generate Encrypted & Signed Package 🔐**.

**What to enter:** A demo recipient key or a locally registered demo user.

**Expected result:** A JSON or PNG package download appears.

**Security demonstrated:** AES-256-GCM payload encryption, RSA-OAEP session-key wrapping, and RSA-PSS sender signatures.

**Viva statement:** “The hybrid design uses AES for the data and RSA for key transport and sender authentication.”

## 12. Trusted Fingerprint and Contact Verification

**What to click:** Open **🔏 Trusted Contacts (Fingerprint Store)**. Inspect **My Public Identity** and **Pinned Contacts**. To add a contact, use **Pin a New Trusted Contact**, fill **Contact Name / Username** and **Contact RSA Public Key (PEM)**, then click **Pin & Trust Contact Key 📌**. During export or import, inspect **Recipient Key Fingerprint** or **Calculated Key Fingerprint**. On an untrusted sender, click **Pin & Trust Key for '<name>' 🔏**. Use **Unpin 🗑️** to remove a pinned contact.

**What to enter:** A demo contact name and its public key through the existing selector or text area.

**Expected result:** The contact is stored with a SHA-256 fingerprint. A matching key reports that it is trusted; a changed key reports key substitution.

**Security demonstrated:** Public-key identity binding through `TrustedKeyStore` rather than trusting a name alone.

**Viva statement:** “Encryption tells us who can decrypt; fingerprint pinning helps establish which public key belongs to the named contact.”

## 13. Demonstrate Tampered Sharing Rejection

**What to click:** In **📥 Verify & Import Package**, upload the demo package, provide the sender key, enter **Master Password**, check **🧪 Demonstrate Security Failure: Simulate Tampered Package (Corrupt Signature / Ciphertext)**, and click **Verify Signature & Decrypt 🔍**.

**What to enter:** The demo sender identity, public key, and recipient password.

**Expected result:** The UI reports **Digital Signature Verification FAILED!** and does not accept the credentials.

**Security demonstrated:** RSA-PSS rejects modified or incorrectly signed package material before import.

**Viva statement:** “A package is not accepted merely because it is readable; its sender signature and encrypted payload must verify.”

## 14. Logout and Session Security

**What to click:** In the sidebar, click **🔒 Lock Vault & Logout**. To demonstrate timeout, leave the session inactive for five minutes.

**What to enter:** Nothing.

**Expected result:** The app returns to the login screen and requires authentication again.

**Security demonstrated:** Centralized cleanup removes derived keys, authentication state, imported credentials, pending values, and dynamic widget state.

**Viva statement:** “The vault is not only protected at rest; the application also clears sensitive session state when the user locks it or becomes inactive.”

## 15. Final Security Summary

The demonstration has shown:

- bcrypt password verification and TOTP second-factor login
- rate limiting, replay prevention, timeout, and cleanup
- AES-256-GCM vault and backup protection with PBKDF2, nonces, tags, and AAD
- safe ciphertext storage preview
- authenticated normal and disaster recovery
- PNG LSB concealment as a separate transport layer
- AES-GCM, RSA-OAEP, RSA-PSS sharing
- SHA-256 fingerprints and `TrustedKeyStore`
- rejection of tampered backups and sharing packages
