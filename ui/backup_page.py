from __future__ import annotations

import streamlit as st

from auth.session import verify_master_password
from stego.embed import create_sample_cover_image, embed_bytes, get_image_capacity
from stego.extract import extract_bytes
from vault.crypto import AuthenticationFailedError


def render(store) -> None:
    st.header("📦 Vault Backup & Steganography")
    st.markdown(
        "Demonstrates two complementary defense layers: "
        "**1. Cryptographic Security:** AES-256-GCM authenticated backup envelope with AAD context binding. "
        "**2. Covert Concealment:** Optional LSB steganographic embedding inside an innocent PNG carrier."
    )

    user = st.session_state.get("user")
    username = st.session_state.get("username")

    if not user or not username:
        st.error("Invalid session. Please log in.")
        return

    backup_tab, restore_tab = st.tabs(
        ["📦 Create Backup (Normal & Stego)", "📥 Restore Vault Backup"]
    )

    # -------------------------------------------------------------
    # TAB 1: CREATE BACKUP
    # -------------------------------------------------------------
    with backup_tab:
        st.subheader("1. Authorization")
        st.caption(
            "Re-enter your master password to authenticate and derive the AES-256-GCM backup key.")

        export_password = st.text_input(
            "Confirm Master Password", type="password", key="export_pass_input"
        )

        st.subheader("2. Backup Format")
        backup_type = st.radio(
            "Select Backup Type",
            [
                "Standard Authenticated Backup (.json) — Cryptographic AEAD Envelope",
                "Covert Steganographic Backup (.png) — Concealed in Image Pixels",
            ],
        )

        cover_bytes = None
        if "Steganographic" in backup_type:
            st.info(
                "💡 **Steganography Note:** Steganography provides *concealment* (making the file look like an ordinary image), "
                "while AES-256-GCM provides the actual *confidentiality and integrity*."
            )
            col_img1, col_img2 = st.columns([2, 1])
            with col_img2:
                if st.button("Generate Sample PNG Carrier 🎨", key="btn_gen_cover"):
                    st.session_state.custom_cover_bytes = create_sample_cover_image(
                        512, 512)
                    st.success("Generated 512x512 cyber gradient PNG!")

            with col_img1:
                uploaded_cover = st.file_uploader(
                    "Upload custom PNG carrier (Optional)", type=["png"], key="cover_uploader"
                )

            if uploaded_cover:
                cover_bytes = uploaded_cover.getvalue()
            elif "custom_cover_bytes" in st.session_state:
                cover_bytes = st.session_state.custom_cover_bytes
            else:
                # Default to generated carrier if none provided
                cover_bytes = create_sample_cover_image(512, 512)

        if st.button("Generate Backup 🔒", type="primary", key="btn_do_export"):
            if not export_password:
                st.error(
                    "Master password is required to generate an authenticated backup.")
            elif not verify_master_password(user, export_password):
                st.error("Authentication failed: incorrect master password.")
            else:
                try:
                    envelope_bytes = store.create_backup_envelope(
                        user, export_password)

                    st.markdown("#### Backup Pipeline:")
                    st.code(
                        f"Original Vault ({username}) ──[PBKDF2 600k + AES-256-GCM]──> Authenticated Envelope ({len(envelope_bytes)} bytes)",
                        language="text",
                    )

                    if "Standard" in backup_type:
                        st.download_button(
                            label="⬇️ Download Authenticated Backup Envelope (.json)",
                            data=envelope_bytes,
                            file_name=f"{username}-vault-backup.json",
                            mime="application/json",
                        )
                        st.success(
                            "✅ Standard authenticated backup envelope created successfully!")
                    else:
                        capacity, (w, h) = get_image_capacity(cover_bytes)
                        if len(envelope_bytes) > capacity:
                            st.error(
                                f"Carrier image too small ({capacity} bytes capacity). Please choose a larger PNG.")
                        else:
                            stego_png = embed_bytes(
                                cover_bytes, envelope_bytes)
                            st.image(
                                stego_png, caption="Steganographic PNG (Visually indistinguishable carrier)", width=280)
                            st.download_button(
                                label="⬇️ Download Stego Backup (PNG)",
                                data=stego_png,
                                file_name=f"{username}-vault-backup.png",
                                mime="image/png",
                            )
                            st.success(
                                "✅ Steganographic backup created! The encrypted envelope is embedded invisibly into the pixel LSBs.")
                except Exception as exc:
                    st.error(f"Failed to generate backup: {exc}")

    # -------------------------------------------------------------
    # TAB 2: IN-SESSION RESTORE
    # -------------------------------------------------------------
    with restore_tab:
        st.subheader("Restore Vault from Backup File")
        st.caption(
            "Supports both standard `.json` backup envelopes and steganographic `.png` carriers. "
            "Requires your master password to authenticate and verify the AEAD tag."
        )

        restore_file = st.file_uploader(
            "Upload Backup File (.json or stego .png)", type=["png", "json"], key="restore_uploader"
        )
        restore_password = st.text_input(
            "Master Password", type="password", key="restore_pass_input"
        )

        simulate_tamper = st.checkbox(
            "🧪 Demonstrate Security Failure: Simulate Tampered Backup File (Bit-Flipping Attack)",
            help="Alters bytes in the backup payload to demonstrate that AES-256-GCM AEAD detects tampering and rejects restoration.",
        )

        if restore_file and st.button("Authenticate and Restore 🔄", type="primary", key="btn_do_restore"):
            if not restore_password:
                st.error(
                    "Master password is required to decrypt and verify the backup envelope.")
            else:
                try:
                    file_bytes = restore_file.getvalue()
                    if restore_file.name.lower().endswith(".png"):
                        raw_extracted = extract_bytes(file_bytes)
                        st.info(
                            f"Steganography layer: extracted {len(raw_extracted)} bytes payload from carrier LSBs.")
                    else:
                        raw_extracted = file_bytes

                    if simulate_tamper:
                        # Intentionally corrupt a byte in the payload to demonstrate AEAD tamper rejection
                        corrupt_byte = b"\xFF" if raw_extracted[-50:-
                                                                49] != b"\xFF" else b"\x00"
                        raw_extracted = raw_extracted[:-50] + \
                            corrupt_byte + raw_extracted[-49:]
                        st.warning(
                            "⚠️ Simulation: Injected 1 corrupted byte into backup envelope.")

                    store.restore_backup_envelope(
                        blob=raw_extracted,
                        password=restore_password,
                        is_in_session=True,
                        current_username=username,
                    )
                    st.success(
                        "✅ Backup authenticated and credentials restored successfully!")
                    st.info("Switching to Dashboard...")
                    st.rerun()

                except AuthenticationFailedError:
                    st.error(
                        "❌ Security Failure Detected: AEAD Authentication Failed! "
                        "The backup file has been modified/tampered with, or the master password was incorrect. "
                        "AES-256-GCM refused to load untrusted data."
                    )
                except Exception as exc:
                    st.error(f"❌ Restoration failed: {exc}")
