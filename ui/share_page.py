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
    st.header("🤝 Secure Vault Sharing & Trusted Keys")
    st.markdown(
        "Mirrors OpenPGP (Lab 6): **Confidentiality** via recipient RSA-2048 public key (OAEP) + "
        "**Payload Authenticity** via AES-256-GCM + **Sender Authentication & Integrity** via RSA-2048 signature (PSS) + "
        "**Identity Binding** via SHA-256 Public Key Fingerprints."
    )

    user = st.session_state.get("user")
    vault_key = st.session_state.get("vault_key")
    username = st.session_state.get("username")

    if not user or not vault_key or not username:
        st.error("Authentication session invalid. Please log in.")
        return

    trusted_store = TrustedKeyStore(store.root)
    trusted_contacts = trusted_store.list_contacts()
    all_local_users = [u for u in store.list_users() if u != username]

    share_tab, import_tab, trust_tab = st.tabs(
        [
            "📤 Export Shared Package",
            "📥 Verify & Import Package",
            "🔏 Trusted Contacts (Fingerprint Store)",
        ]
    )

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
        else:
            cred_options = {f"{c.site} ({c.username})": c for c in credentials}
            selected_labels = st.multiselect(
                "Choose credentials to include in the package",
                options=list(cred_options.keys()),
                default=list(cred_options.keys()),
            )

            st.subheader("2. Recipient Public Key & Fingerprint Verification")

            recipient_mode = st.radio(
                "Recipient Selection",
                ["From Trusted Contacts / Local Users", "Manual PEM Input"],
                horizontal=True,
            )

            recipient_key = ""
            rec_name = ""

            if recipient_mode == "From Trusted Contacts / Local Users":
                combined_options = list(trusted_contacts.keys()) + [
                    u for u in all_local_users if u not in trusted_contacts
                ]
                if combined_options:
                    selected_rec = st.selectbox(
                        "Select Recipient Contact", combined_options)
                    rec_name = selected_rec
                    if selected_rec in trusted_contacts:
                        recipient_key = trusted_contacts[selected_rec]["public_key"]
                    else:
                        rec_user_doc = store.load_user(selected_rec)
                        if rec_user_doc and "public_key" in rec_user_doc:
                            recipient_key = rec_user_doc["public_key"]
                else:
                    st.info(
                        "No other users found. Switch to 'Manual PEM Input' or register a second user.")
            else:
                rec_name = st.text_input(
                    "Recipient Name", placeholder="e.g. bob").strip()
                recipient_key = st.text_area(
                    "Recipient RSA Public Key (PEM)", height=120, key="manual_rec_key"
                ).strip()

            if recipient_key:
                rec_fp = get_key_fingerprint(recipient_key)
                st.write(f"**Recipient Key Fingerprint:** `{rec_fp}`")

                # Check fingerprint against trusted contacts
                if rec_name and rec_name.lower() in trusted_contacts:
                    is_trusted, msg = trusted_store.verify_trust(
                        rec_name, recipient_key)
                    if is_trusted:
                        st.success(f"✅ {msg}")
                    else:
                        st.error(f"🚨 {msg}")

            st.subheader("3. Sender Authorization")
            st.caption(
                "Enter your master password to unlock your RSA private key for signing.")
            sender_pass = st.text_input(
                "Master Password", type="password", key="share_sender_pass")

            package_format = st.radio(
                "Package Delivery Channel",
                ["Standard JSON Security Package (.json)",
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
                        payload_bytes = json.dumps(
                            payload_data).encode("utf-8")

                        # Decrypt sender private key using master password
                        sender_private_pem = store.private_key(
                            user, sender_pass)

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
                            stego_share = create_stego_share_package(
                                package_bytes)
                            st.download_button(
                                label="⬇️ Download Covert Steganographic Package (.png)",
                                data=stego_share,
                                file_name=f"share-from-{username}.png",
                                mime="image/png",
                            )
                        st.success(
                            "✅ Hybrid package encrypted (AES-256-GCM) and digitally signed (RSA-PSS) successfully!")

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

        st.subheader("2. Sender Identity & Public Key")
        sender_name_in = st.text_input(
            "Claimed Sender Username", placeholder="e.g. alice").strip()

        # Quick picker from trusted contacts or registered users
        combined_senders = list(trusted_contacts.keys()) + [
            u for u in all_local_users if u not in trusted_contacts
        ]
        if combined_senders:
            picked_sender = st.selectbox(
                "Quick-fill sender key from Contacts / Local Users:",
                ["-- Manual Paste --"] + combined_senders,
                key="sel_sender_picker",
            )
            if picked_sender != "-- Manual Paste --":
                sender_name_in = picked_sender
                if picked_sender in trusted_contacts:
                    st.session_state.sender_key_val = trusted_contacts[picked_sender]["public_key"]
                else:
                    s_rec = store.load_user(picked_sender)
                    if s_rec and "public_key" in s_rec:
                        st.session_state.sender_key_val = s_rec["public_key"]

        sender_public_key = st.text_area(
            "Sender RSA Public Key (for PSS signature verification)",
            value=st.session_state.get("sender_key_val", ""),
            height=120,
            key="input_sender_key",
        ).strip()

        if sender_public_key:
            sender_fp = get_key_fingerprint(sender_public_key)
            st.write(f"**Calculated Key Fingerprint:** `{sender_fp}`")

            # Perform identity / trust check
            if sender_name_in and sender_name_in.lower() in trusted_contacts:
                is_trusted, msg = trusted_store.verify_trust(
                    sender_name_in, sender_public_key)
                if is_trusted:
                    st.success(f"✅ {msg}")
                else:
                    st.error(f"🚨 {msg}")
            elif sender_name_in:
                st.warning(
                    f"⚠️ Untrusted Sender Key: Contact '{sender_name_in}' is not in your Trusted Key Store. "
                    "Remember: Encryption proves confidentiality, but only fingerprint pinning proves identity!"
                )
                if st.button(f"Pin & Trust Key for '{sender_name_in}' 🔏"):
                    trusted_store.trust_key(sender_name_in, sender_public_key)
                    st.success(f"Key pinned for '{sender_name_in}'!")
                    st.rerun()

        st.subheader("3. Decryption Authorization")
        st.caption(
            "Enter your master password to unlock your RSA private key to decrypt.")
        import_pass = st.text_input(
            "Master Password", type="password", key="import_pass_input"
        )

        # Interactive Security Failure Demonstration (Demo 8)
        simulate_tamper = st.checkbox(
            "🧪 Demonstrate Security Failure: Simulate Tampered Package (Corrupt Signature / Ciphertext)",
            help="Modifies the package bytes to demonstrate that RSA-PSS signature verification detects tampering and rejects the package.",
        )

        if uploaded_pkg and st.button("Verify Signature & Decrypt 🔍", type="primary", key="btn_verify_pkg"):
            if not sender_public_key:
                st.error(
                    "Please provide the sender's RSA public key to verify authenticity.")
            elif not import_pass:
                st.error("Master password is required to decrypt the package.")
            elif not verify_master_password(user, import_pass):
                st.error("Authentication failed: incorrect master password.")
            else:
                # Key substitution check
                trusted_ok = True
                if sender_name_in and sender_name_in.lower() in trusted_contacts:
                    is_trusted, msg = trusted_store.verify_trust(
                        sender_name_in, sender_public_key)
                    if not is_trusted:
                        st.error(
                            f"❌ Security Failure Demo: Key Substitution Detected! "
                            f"{msg} Decryption aborted to prevent MITM impersonation."
                        )
                        trusted_ok = False

                if trusted_ok:
                    try:
                        file_bytes = uploaded_pkg.getvalue()
                        if uploaded_pkg.name.lower().endswith(".png"):
                            package_bytes = open_stego_share_package(
                                file_bytes)
                            st.info(
                                "Steganography layer: Extracted PGP package from PNG carrier.")
                        else:
                            package_bytes = file_bytes

                        if simulate_tamper:
                            pkg_obj = json.loads(package_bytes.decode("utf-8"))
                            # Corrupt signature to trigger VerificationError
                            pkg_obj["signature"] = "A" + \
                                pkg_obj["signature"][1:]
                            package_bytes = json.dumps(pkg_obj).encode("utf-8")
                            st.warning(
                                "⚠️ Simulation: Injected forged signature into package.")

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

                    except VerificationError:
                        st.error(
                            "❌ Security Failure Detected: Digital Signature Verification FAILED! "
                            "The package was modified, corrupted in transit, or was not signed by this sender. "
                            "RSA-PSS refused to accept untrusted data."
                        )
                    except DecryptionError:
                        st.error(
                            "❌ Decryption Failed: You do not possess the matching RSA private key for this package, "
                            "or the AEAD authentication tag failed."
                        )
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

    # -------------------------------------------------------------
    # TAB 3: TRUSTED CONTACTS & FINGERPRINT STORE
    # -------------------------------------------------------------
    with trust_tab:
        st.subheader("🔏 Trusted Key Store (Fingerprint Pinning)")
        st.markdown(
            "This area manages trusted identity bindings. "
            "**Key Principle:** *Encryption guarantees confidentiality, but only Fingerprint Verification & Pinning guarantees identity.*"
        )

        my_public_pem = user.get("public_key", "")
        my_fp = get_key_fingerprint(my_public_pem)
        with st.expander("🔑 My Public Identity (Share this with contacts)"):
            st.write(f"**My Username:** `{username}`")
            st.write(f"**My SHA-256 Fingerprint:** `{my_fp}`")
            st.code(my_public_pem, language="text")

        st.divider()
        st.subheader("Pinned Contacts")
        current_contacts = trusted_store.list_contacts()

        if not current_contacts:
            st.info("No contacts currently pinned in your Trusted Key Store.")
        else:
            for c_name, c_data in current_contacts.items():
                with st.container(border=True):
                    col_c1, col_c2 = st.columns([3, 1])
                    with col_c1:
                        st.write(f"👤 **{c_data.get('contact_name', c_name)}**")
                        st.code(
                            f"Fingerprint: {c_data.get('fingerprint')}", language="text")
                    with col_c2:
                        if st.button("Unpin 🗑️", key=f"unpin_{c_name}"):
                            trusted_store.remove_contact(c_name)
                            st.success(f"Unpinned contact '{c_name}'.")
                            st.rerun()

        st.divider()
        st.subheader("Pin a New Trusted Contact")
        with st.form("pin_contact_form", clear_on_submit=True):
            new_contact_name = st.text_input(
                "Contact Name / Username", placeholder="e.g. bob")
            new_contact_pem = st.text_area("Contact RSA Public Key (PEM)")

            if st.form_submit_button("Pin & Trust Contact Key 📌", type="primary"):
                if not new_contact_name or not new_contact_pem:
                    st.error("Both contact name and public key PEM are required.")
                else:
                    try:
                        pinned_fp = trusted_store.trust_key(
                            new_contact_name, new_contact_pem)
                        st.success(
                            f"✅ Contact '{new_contact_name}' pinned with Fingerprint: `{pinned_fp}`!")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to pin key: {exc}")
