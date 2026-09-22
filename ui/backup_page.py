from __future__ import annotations

import streamlit as st

from auth.session import verify_master_password
from stego.embed import create_sample_cover_image, embed_bytes, get_image_capacity
from stego.extract import extract_bytes


def render(store) -> None:
    st.header("🖼️ Steganographic Covert Backups")
    st.markdown(
        "Embeds your **authenticated AES-256-GCM backup envelope** invisibly into the least significant bits (LSBs) "
        "of a PNG cover image. Steganography provides covert concealment; data integrity and confidentiality are strictly enforced by AEAD."
    )

    user = st.session_state.get("user")
    username = st.session_state.get("username")

    if not user or not username:
        st.error("Invalid session. Please log in.")
        return

    backup_tab, restore_tab = st.tabs(
        ["📦 Export Authenticated Backup", "📥 Restore In-Session Backup"])

    # -------------------------------------------------------------
    # TAB 1: EXPORT BACKUP
    # -------------------------------------------------------------
    with backup_tab:
        st.subheader("1. Re-authenticate for Export")
        st.caption(
            "Re-enter your master password to authenticate and seal the backup envelope.")

        export_password = st.text_input(
            "Confirm Master Password", type="password", key="export_pass_input")

        st.subheader("2. Select Cover Image (Optional Concealment)")
        col_img1, col_img2 = st.columns([2, 1])
        with col_img2:
            if st.button("Generate Sample Cover Image 🎨", key="btn_gen_cover"):
                st.session_state.custom_cover_bytes = create_sample_cover_image(
                    512, 512)
                st.success("Generated 512x512 cyber gradient cover image!")

        with col_img1:
            uploaded_cover = st.file_uploader(
                "Upload a PNG image", type=["png"], key="cover_uploader"
            )

        cover_bytes = None
        if uploaded_cover:
            cover_bytes = uploaded_cover.getvalue()
        elif "custom_cover_bytes" in st.session_state:
            cover_bytes = st.session_state.custom_cover_bytes

        if st.button("Generate Authenticated Backup Envelope 🔒", type="primary", key="btn_do_export"):
            if not export_password:
                st.error(
                    "Master password is required to generate an authenticated backup.")
            elif not verify_master_password(user, export_password):
                st.error("Authentication failed: incorrect master password.")
            else:
                try:
                    envelope_bytes = store.create_backup_envelope(
                        user, export_password)

                    # If cover image is available, offer both PNG and JSON
                    if cover_bytes:
                        try:
                            capacity, _ = get_image_capacity(cover_bytes)
                            if len(envelope_bytes) > capacity:
                                st.warning(
                                    f"Cover image capacity ({capacity} bytes) too small. Providing JSON envelope instead.")
                                st.download_button(
                                    label="⬇️ Download Backup Envelope (.json)",
                                    data=envelope_bytes,
                                    file_name=f"{username}-vault-backup.json",
                                    mime="application/json",
                                )
                            else:
                                stego_png = embed_bytes(
                                    cover_bytes, envelope_bytes)
                                st.download_button(
                                    label="⬇️ Download Covert Stego Backup (PNG)",
                                    data=stego_png,
                                    file_name=f"{username}-vault-backup.png",
                                    mime="image/png",
                                )
                                st.success(
                                    "Covert backup created! The visible image remains an ordinary PNG.")
                        except Exception:
                            st.warning(
                                "Stego embedding failed. Providing authenticated JSON envelope instead.")
                            st.download_button(
                                label="⬇️ Download Backup Envelope (.json)",
                                data=envelope_bytes,
                                file_name=f"{username}-vault-backup.json",
                                mime="application/json",
                            )
                    else:
                        st.download_button(
                            label="⬇️ Download Authenticated Backup Envelope (.json)",
                            data=envelope_bytes,
                            file_name=f"{username}-vault-backup.json",
                            mime="application/json",
                        )
                        st.success(
                            "Authenticated backup envelope generated successfully.")

                    st.session_state.pop("export_pass_input", None)
                except Exception:
                    st.error("Failed to generate backup envelope.")

    # -------------------------------------------------------------
    # TAB 2: IN-SESSION RESTORE
    # -------------------------------------------------------------
    with restore_tab:
        st.subheader("Restore Vault from Backup")
        st.caption(
            "Extracts and authenticates your backup envelope. Requires your master password "
            "and verifies that the backup matches your active account."
        )

        restore_file = st.file_uploader(
            "Upload Stego-PNG or Backup JSON", type=["png", "json"], key="restore_uploader"
        )
        restore_password = st.text_input(
            "Master Password", type="password", key="restore_pass_input")

        if restore_file and st.button("Authenticate and Restore 🔄", type="primary", key="btn_do_restore"):
            if not restore_password:
                st.error(
                    "Master password is required to decrypt and verify the backup envelope.")
            else:
                try:
                    file_bytes = restore_file.getvalue()
                    if restore_file.name.lower().endswith(".png"):
                        raw_extracted = extract_bytes(file_bytes)
                    else:
                        raw_extracted = file_bytes

                    store.restore_backup_envelope(
                        blob=raw_extracted,
                        password=restore_password,
                        is_in_session=True,
                        current_username=username,
                    )
                    st.success(
                        "✅ Backup authenticated and credentials restored successfully!")
                    st.session_state.pop("restore_pass_input", None)
                    st.info("Switching to Dashboard...")
                    st.rerun()
                except Exception as exc:
                    st.error(f"❌ Restoration failed: {exc}")
