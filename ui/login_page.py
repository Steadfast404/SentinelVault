from __future__ import annotations

import streamlit as st

from auth.hashing import hash_password
from auth.session import (
    is_locked_out,
    record_failed_attempt,
    reset_failed_attempts,
    verify_master_password,
    verify_totp,
)
from auth.totp import generate_qr_code_image, generate_secret, get_totp_uri
from sharing.keys import generate_keypair
from stego.extract import extract_bytes
from vault.crypto import derive_vault_key
import base64


def render_step_indicator(current_step: int) -> None:
    """Render a visual defense-in-depth step progress bar for authentication."""
    cols = st.columns(3)
    steps = [
        ("Layer 1: Master Password", "bcrypt Salted Hash", 1),
        ("Layer 2: Two-Factor Auth", "TOTP RFC 6238", 2),
        ("Layer 3: Vault Access", "AES-256-GCM AEAD", 3),
    ]
    for col, (title, desc, num) in zip(cols, steps):
        with col:
            if current_step > num:
                st.success(f"✅ **{title}**\n\n*{desc}*")
            elif current_step == num:
                st.info(f"⏳ **{title}**\n\n*{desc}*")
            else:
                st.caption(f"🔒 **{title}**\n\n*{desc}*")
    st.divider()


def render(store) -> None:
    st.title("🛡️ SentinelVault")
    st.markdown(
        "**Defense-in-Depth Local Password Vault** — Layered with `bcrypt`, `TOTP 2FA`, `AES-256-GCM AEAD`, `LSB Steganography (Concealment)`, and `PGP (RSA+PSS)`."
    )

    if st.session_state.get("session_timed_out", False):
        st.warning(
            "⚠️ Session expired due to inactivity. Please authenticate to unlock your vault.")
        st.session_state["session_timed_out"] = False

    tabs = st.tabs(
        ["🔑 Unlock Vault", "✨ Create New Vault", "🔄 Disaster Recovery"])

    # -------------------------------------------------------------
    # TAB 1: UNLOCK VAULT (SEQUENTIAL TWO-STEP 2FA GATE)
    # -------------------------------------------------------------
    with tabs[0]:
        if "login_stage" not in st.session_state:
            st.session_state.login_stage = "password"

        # Stage 1: Master Password Check
        if st.session_state.login_stage == "password":
            render_step_indicator(1)
            st.subheader("Step 1 of 2: Master Password Verification")
            st.caption(
                "Verifies against salted one-way bcrypt hash (Work Factor = 12).")

            username = st.text_input(
                "Username", key="login_user_input").strip()
            password = st.text_input(
                "Master Password", type="password", key="login_pass_input")

            # Check if user is currently locked out
            user_locked = False
            if username:
                locked, seconds_left = is_locked_out(username)
                if locked:
                    st.error(
                        f"⛔ Account temporarily locked due to repeated failed attempts. Please wait {seconds_left}s."
                    )
                    user_locked = True

            if st.button("Continue to Second Factor ➡️", type="primary", key="btn_check_password"):
                if user_locked:
                    st.error("⛔ Account is currently locked. Please wait.")
                elif not username or not password:
                    st.warning(
                        "Please provide both username and master password.")
                else:
                    locked, seconds_left = is_locked_out(username)
                    if locked:
                        st.error(
                            f"⛔ Account locked. Wait {seconds_left}s before retrying.")
                    else:
                        user = store.load_user(username)
                        if not user or not verify_master_password(user, password):
                            attempts, newly_locked = record_failed_attempt(
                                username)
                            if newly_locked:
                                st.error(
                                    "⛔ Maximum failed attempts reached. Account locked for 60 seconds.")
                            else:
                                st.error(
                                    f"❌ Authentication failed. Attempt {attempts}/5.")
                        else:
                            try:
                                store.migrate_legacy_user(user, password)
                            except Exception:
                                st.error(
                                    "This vault uses an unsupported legacy encryption format and could not be migrated.")
                                user = None

                            if user:
                                # Derive vault key in memory; never store plaintext master password in session_state!
                                salt = base64.b64decode(user["vault_salt"])
                                vault_key = derive_vault_key(password, salt)

                                st.session_state.pending_user = user
                                st.session_state.pending_username = user["username"]
                                st.session_state.temp_vault_key = vault_key
                                st.session_state.login_stage = "otp"
                                st.rerun()

        # Stage 2: 2FA TOTP Check
        elif st.session_state.login_stage == "otp":
            render_step_indicator(2)
            st.subheader("Step 2 of 2: Time-Based One-Time Password (TOTP)")
            st.caption(
                "Enter the 6-digit code from your authenticator app (RFC 6238).")

            otp_input = st.text_input(
                "6-digit Authenticator Code", max_chars=6, key="login_otp_input")

            col1, col2 = st.columns([2, 1])
            with col1:
                if st.button("Unlock Vault 🔓", type="primary", key="btn_verify_otp"):
                    username = st.session_state.get("pending_username", "")
                    user = st.session_state.get("pending_user")
                    vault_key = st.session_state.get("temp_vault_key")

                    if not otp_input or len(otp_input.strip()) != 6:
                        st.warning(
                            "Please enter a valid 6-digit numeric OTP code.")
                    elif not user or not vault_key:
                        st.error(
                            "Authentication session expired. Please start over.")
                        st.session_state.login_stage = "password"
                        st.rerun()
                    else:
                        # Check lockout before verifying OTP
                        locked, seconds_left = is_locked_out(username)
                        if locked:
                            st.error(
                                f"⛔ Account locked due to failed attempts. Please wait {seconds_left}s.")
                        elif verify_totp(user, otp_input):
                            # Both factors verified!
                            reset_failed_attempts(username)
                            st.session_state.authenticated = True
                            st.session_state.user = user
                            st.session_state.username = username
                            st.session_state.vault_key = vault_key

                            # Purge all pending stage variables
                            st.session_state.login_stage = "password"
                            st.session_state.pop("pending_user", None)
                            st.session_state.pop("pending_username", None)
                            st.session_state.pop("temp_vault_key", None)
                            st.rerun()
                        else:
                            # CRITICAL: OTP failures must trigger lockout tracking!
                            attempts, newly_locked = record_failed_attempt(
                                username)
                            if newly_locked:
                                st.error(
                                    "⛔ Maximum failed attempts reached. Account locked for 60 seconds.")
                                st.session_state.login_stage = "password"
                                st.session_state.pop("pending_user", None)
                                st.session_state.pop("pending_username", None)
                                st.session_state.pop("temp_vault_key", None)
                                st.rerun()
                            else:
                                st.error(
                                    f"❌ Invalid or expired authenticator code! Attempt {attempts}/5.")

            with col2:
                if st.button("Cancel / Back"):
                    st.session_state.login_stage = "password"
                    st.session_state.pop("pending_user", None)
                    st.session_state.pop("pending_username", None)
                    st.session_state.pop("temp_vault_key", None)
                    st.rerun()

    # -------------------------------------------------------------
    # TAB 2: CREATE NEW VAULT (REGISTRATION)
    # -------------------------------------------------------------
    with tabs[1]:
        st.subheader("Register a New Protected Vault")
        st.caption(
            "Initializes PBKDF2 salt, bcrypt hash, TOTP seed, and RSA-2048 identity keypair.")

        reg_username = st.text_input("Choose Username", key="reg_user").strip()
        reg_password = st.text_input(
            "Master Password", type="password", key="reg_pass")
        reg_confirm = st.text_input(
            "Confirm Master Password", type="password", key="reg_confirm")

        if st.button("Initialize & Generate Keys 🛡️", type="primary", key="btn_create_user"):
            if not reg_username or not reg_password:
                st.error("Username and master password are required.")
            elif reg_password != reg_confirm:
                st.error("Passwords do not match.")
            elif len(reg_password) < 8:
                st.error("Master password should be at least 8 characters.")
            elif store.load_user(reg_username):
                st.error(
                    f"Username '{reg_username}' already exists. Please choose a different username.")
            else:
                try:
                    secret = generate_secret()
                    private_pem, public_pem = generate_keypair()
                    hashed = hash_password(reg_password)
                    user = store.create_user(
                        username=reg_username,
                        password=reg_password,
                        password_hash=hashed,
                        totp_secret=secret,
                        private_key=private_pem,
                        public_key=public_pem,
                    )
                    st.session_state.new_registration = {
                        "username": reg_username,
                        "secret": secret,
                    }
                    st.success(
                        f"Vault for '{reg_username}' initialized successfully!")
                except Exception as exc:
                    st.error(f"Registration failed: {exc}")

        if "new_registration" in st.session_state:
            reg_info = st.session_state.new_registration
            st.divider()
            st.subheader(
                "📱 Two-Factor Authentication Setup (One-Time Enrollment)")
            st.warning(
                "⚠️ This secret is displayed ONLY ONCE during setup and will never be rendered again. "
                "Scan this QR code with Google Authenticator, Microsoft Authenticator, or 2FAS."
            )

            uri = get_totp_uri(reg_info["secret"], reg_info["username"])
            qr_bytes = generate_qr_code_image(uri)

            qr_col, text_col = st.columns([1, 2])
            with qr_col:
                st.image(
                    qr_bytes, caption="Scan with Authenticator App", width=220)
            with text_col:
                st.write("**TOTP Secret (Base32):**")
                st.code(reg_info["secret"], language="text")

            if st.button("✅ I have safely stored my TOTP secret", key="btn_confirm_totp_saved"):
                st.session_state.pop("new_registration", None)
                st.success(
                    "Enrollment complete! Switch to 'Unlock Vault' to log in.")
                st.rerun()

    # -------------------------------------------------------------
    # TAB 3: DISASTER RECOVERY (AUTHENTICATED RECOVERY ONLY)
    # -------------------------------------------------------------
    with tabs[2]:
        st.subheader("🔄 Authenticated Disaster Recovery")
        st.write(
            "Recover a missing or wiped vault using your SentinelVault backup file or stego-PNG. "
            "Unauthenticated disaster recovery requires **both** your master password and your current 6-digit TOTP code, "
            "and **will refuse** to overwrite an existing account on disk."
        )
        backup_file = st.file_uploader(
            "Select SentinelVault Backup (.json or stego .png)",
            type=["png", "json"],
            key="recovery_file_uploader",
        )
        rec_password = st.text_input(
            "Master Password", type="password", key="rec_pass_input")
        rec_otp = st.text_input(
            "Current 6-digit TOTP Code", max_chars=6, key="rec_otp_input")

        simulate_tamper = st.checkbox(
            "🧪 Demonstrate Security Failure: Simulate Tampered Backup File",
            help="Alters bytes in the backup envelope to demonstrate that disaster recovery detects tampering and rejects unauthenticated files.",
            key="rec_simulate_tamper",
        )

        if backup_file and st.button("Authenticate and Restore Account", type="primary"):
            if not rec_password or not rec_otp:
                st.error(
                    "Both master password and 6-digit authenticator code are required for disaster recovery.")
            else:
                try:
                    file_bytes = backup_file.getvalue()
                    if backup_file.name.lower().endswith(".png"):
                        extracted_blob = extract_bytes(file_bytes)
                    else:
                        extracted_blob = file_bytes

                    if simulate_tamper:
                        corrupt_byte = b"\xFF" if extracted_blob[-50:-
                                                                 49] != b"\xFF" else b"\x00"
                        extracted_blob = extracted_blob[:-50] + \
                            corrupt_byte + extracted_blob[-49:]
                        st.warning(
                            "⚠️ Simulation: Injected 1 corrupted byte into backup envelope.")

                    restored_user = store.restore_backup_envelope(
                        blob=extracted_blob,
                        password=rec_password,
                        totp_code=rec_otp,
                        is_in_session=False,
                    )
                    st.success(
                        f"✅ Successfully authenticated and restored account '{restored_user['username']}'! "
                        "You can now switch to 'Unlock Vault' and sign in."
                    )
                except Exception as exc:
                    st.error(f"❌ Recovery failed: {exc}")
