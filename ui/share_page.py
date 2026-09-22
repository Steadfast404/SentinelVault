from __future__ import annotations

import json
import streamlit as st

from auth.session import verify_master_password
from sharing.keys import TrustedKeyStore, get_key_fingerprint
from sharing.pgp_exchange import (
    DecryptionError,
    VerificationError,
    create_package,
    create_stego_share_package,
    open_package,
    open_stego_share_package,
)
from vault.models import Credential


def render(store) -> None:
    st.header("🤝 Secure Vault Sharing (PGP Layer)")
    st.markdown(
        "Mirrors OpenPGP: **Confidentiality** via recipient's RSA-2048 public key (OAEP) + "
        "**Payload Authenticity** via AES-256-GCM + **Sender Authenticity & Integrity** via RSA-2048 private key (PSS)."
    )

    user = st.session_state.get("user")
    vault_key = st.session_state.get("vault_key")
    username = st.session_state.get("username")

    if not user or not vault_key or not username:
        st.error("Authentication session invalid. Please log in.")
        return

    trusted_store = TrustedKeyStore(store.root)

    share_tab, import_tab = st.tabs(
        ["📤 Export Shared Package", "📥 Verify & Import Package"])

    # Show current user's public key & fingerprint
    my_public_pem = user.get("public_key", "")
    my_fingerprint = get_key_fingerprint(my_public_pem)
    with st.expander("🔑 My Public Identity"):
        st.write(f"**SHA-256 Fingerprint:** `{my_fingerprint}`")
        st.code(my_public_pem, language="text")
        st.caption(
            "Others need this public key to securely share credentials with you.")

    # -------------------------------------------------------------
    # TAB 1: EXPORT SHARED PACKAGE
    # -------------------------------------------------------------
    with share_tab:
        st.subheader("1. Select Credentials to Share")
        try:
            credentials = store.read_credentials(user, vault_key)
        except Exception:
            credentials = []

        if not credentials:
            st.warning(
                "Your vault is empty. Add credentials in the Dashboard before sharing.")
            return

        cred_options = {f"{c.site} ({c.username})": c for c in credentials}
        selected_labels = st.multiselect(
            "Choose credentials to include in the package",
            options=list(cred_options.keys()),
            default=list(cred_options.keys()),
        )

        st.subheader("2. Recipient Identity & Fingerprint Verification")

        other_users = [u for u in store.list_users() if u != username]
        if other_users:
            selected_user = st.selectbox(
                "Quick-fill public key from registered test user:",
                ["-- Manual Paste --"] + other_users,
            )
            if selected_user != "-- Manual Paste --":
                rec_record = store.load_user(selected_user)
                if rec_record and "public_key" in rec_record:
                    st.session_state.recipient_key_val = rec_record["public_key"]

        recipient_key = st.text_area(
            "Recipient RSA Public Key (PEM format)",
            value=st.session_state.get("recipient_key_val", ""),
            height=130,
            key="input_recipient_key",
        ).strip()

        if recipient_key:
            rec_fp = get_key_fingerprint(recipient_key)
            st.write(f"**Recipient Fingerprint:** `{rec_fp}`")

        st.subheader("3. Sender Authorization")
        st.caption(
            "Enter your master password to unlock your RSA private key for signing.")
        sender_pass = st.text_input(
            "Master Password", type="password", key="share_sender_pass")

        package_format = st.radio(
            "Delivery Channel",
            ["JSON Security Package (.json)",
             "Covert Steganographic PNG (.png)"],
        )

        if st.button("Generate Encrypted & Signed Package 🔐", type="primary", key="btn_create_share"):
            if not selected_labels:
                st.error("Please select at least one credential to share.")
            elif not recipient_key:
                st.error("Please provide the recipient's RSA public key.")
            elif not sender_pass:
                st.error("Master password is required to sign the package.")
            elif not verify_master_password(user, sender_pass):
                st.error("Authentication failed: incorrect master password.")
            else:
                try:
                    payload_data = [cred_options[label].to_dict()
                                    for label in selected_labels]
                    payload_bytes = json.dumps(payload_data).encode("utf-8")

                    # Decrypt sender private key using master password
                    sender_private_pem = store.private_key(user, sender_pass)

                    package_bytes = create_package(
                        payload=payload_bytes,
                        recipient_public_pem=recipient_key,
                        sender_private_pem=sender_private_pem,
                        sender_username=username,
                    )

                    if "JSON" in package_format:
                        st.download_button(
                            label="⬇️ Download Security Package (.json)",
                            data=package_bytes,
                            file_name=f"share-from-{username}.json",
                            mime="application/json",
                        )
                    else:
                        stego_share = create_stego_share_package(package_bytes)
                        st.download_button(
                            label="⬇️ Download Covert Steganographic Package (.png)",
                            data=stego_share,
                            file_name=f"share-from-{username}.png",
                            mime="image/png",
                        )
                    st.success(
                        "✅ Hybrid package encrypted (AES-256-GCM) and digitally signed (RSA-PSS) successfully!")
                    st.session_state.pop("share_sender_pass", None)

                except Exception as exc:
                    st.error(f"❌ Failed to create package: {exc}")

    # -------------------------------------------------------------
    # TAB 2: VERIFY & IMPORT PACKAGE
    # -------------------------------------------------------------
    with import_tab:
        st.subheader("1. Upload Shared Package")
        uploaded_pkg = st.file_uploader(
            "Upload package file (.json or stego .png)",
            type=["json", "png"],
            key="pkg_uploader",
        )

        st.subheader("2. Sender's Public Key for Authentication")
        if other_users:
            sender_sel = st.selectbox(
                "Quick-fill sender public key from registered test user:",
                ["-- Manual Paste --"] + other_users,
                key="sel_sender_picker",
            )
            if sender_sel != "-- Manual Paste --":
                sender_rec = store.load_user(sender_sel)
                if sender_rec and "public_key" in sender_rec:
                    st.session_state.sender_key_val = sender_rec["public_key"]

        sender_public_key = st.text_area(
            "Sender RSA Public Key (for PSS signature verification)",
            value=st.session_state.get("sender_key_val", ""),
            height=130,
            key="input_sender_key",
        ).strip()

        st.subheader("3. Decryption Authorization")
        st.caption(
            "Enter your master password to unlock your RSA private key to decrypt.")
        import_pass = st.text_input(
            "Master Password", type="password", key="import_pass_input")

        if uploaded_pkg and st.button("Verify Signature & Decrypt 🔍", type="primary", key="btn_verify_pkg"):
            if not sender_public_key:
                st.error(
                    "Please provide the sender's RSA public key to verify authenticity.")
            elif not import_pass:
                st.error("Master password is required to decrypt the package.")
            elif not verify_master_password(user, import_pass):
                st.error("Authentication failed: incorrect master password.")
            else:
                try:
                    file_bytes = uploaded_pkg.getvalue()
                    if uploaded_pkg.name.lower().endswith(".png"):
                        package_bytes = open_stego_share_package(file_bytes)
                    else:
                        package_bytes = file_bytes

                    my_private_pem = store.private_key(user, import_pass)

                    decrypted_payload, meta = open_package(
                        package=package_bytes,
                        recipient_private_pem=my_private_pem,
                        sender_public_pem=sender_public_key,
                    )

                    shared_credentials_raw = json.loads(
                        decrypted_payload.decode("utf-8"))
                    st.session_state.verified_incoming = {
                        "credentials": [Credential.from_dict(d) for d in shared_credentials_raw],
                        "meta": meta,
                    }

                    st.success(
                        f"✅ Digital signature and AEAD integrity VERIFIED! Authenticated sender: '{meta['sender']}' "
                        f"(Fingerprint: `{meta['sender_fingerprint']}`)."
                    )
                    st.session_state.pop("import_pass_input", None)

                except VerificationError as v_err:
                    st.error(f"❌ {v_err}")
                except DecryptionError as d_err:
                    st.error(f"❌ {d_err}")
                except Exception as exc:
                    st.error(f"❌ Verification failed: {exc}")

        # If incoming credentials were authenticated, display preview with Merge / Discard
        if "verified_incoming" in st.session_state:
            incoming = st.session_state.verified_incoming
            st.divider()
            st.subheader(
                f"📦 Authenticated Credentials from '{incoming['meta']['sender']}'")

            for c in incoming["credentials"]:
                with st.container(border=True):
                    st.write(
                        f"**Site:** `{c.site}` | **Username:** `{c.username}`")
                    st.code("••••••••••••••••", language="text")

            col_m1, col_m2 = st.columns([1, 1])
            with col_m1:
                if st.button("Merge into My Vault 📥", type="primary", key="btn_merge_creds"):
                    my_creds = store.read_credentials(user, vault_key)
                    existing_sites = {
                        f"{c.site}:{c.username}" for c in my_creds}
                    added_count = 0

                    for inc_c in incoming["credentials"]:
                        key_tag = f"{inc_c.site}:{inc_c.username}"
                        if key_tag not in existing_sites:
                            my_creds.append(inc_c)
                            existing_sites.add(key_tag)
                            added_count += 1

                    store.write_credentials(user, vault_key, my_creds)
                    store.save_user(username, user)
                    st.session_state.pop("verified_incoming", None)
                    st.success(
                        f"✅ Successfully merged {added_count} new credential(s) into your vault!")
                    st.rerun()
            with col_m2:
                if st.button("Discard Credentials ❌", key="btn_discard_creds"):
                    st.session_state.pop("verified_incoming", None)
                    st.rerun()
