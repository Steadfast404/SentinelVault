from __future__ import annotations

import streamlit as st

from vault.crypto import evaluate_password_strength, generate_password
from vault.models import Credential


def render(store) -> None:
    st.header("🔐 Vault Dashboard")
    st.caption(
        "Protected by AES-256-GCM AEAD with fresh random 96-bit nonces. Decrypted in-memory only.")

    user = st.session_state.get("user")
    vault_key = st.session_state.get("vault_key")

    if not user or not vault_key:
        st.error("Authentication session invalid. Please log in.")
        return

    # Read credentials from vault using ephemeral in-memory vault_key
    try:
        credentials = store.read_credentials(user, vault_key)
    except Exception:
        st.error(
            "Failed to authenticate or decrypt vault data. Integrity check failed.")
        return

    # Top summary metrics
    col_stat1, col_stat2, col_stat3 = st.columns(3)
    with col_stat1:
        st.metric("Total Credentials", len(credentials))
    with col_stat2:
        st.metric("Encryption Standard", "AES-256-GCM (AEAD)")
    with col_stat3:
        st.metric("Key Derivation", "PBKDF2 (600,000 rounds)")

    st.divider()

    # -----------------------------------------------------------------
    # SECTION: ADD NEW CREDENTIAL (WITH GENERATOR & STRENGTH METER)
    # -----------------------------------------------------------------
    with st.expander("➕ Add New Credential", expanded=(len(credentials) == 0)):
        st.subheader("Credential Details")

        # Optional random password generator controls
        with st.popover("🎲 Generate Secure Password"):
            gen_len = st.slider("Password Length",
                                min_value=8, max_value=32, value=16)
            col_g1, col_g2 = st.columns(2)
            with col_g1:
                use_upper = st.checkbox("Uppercase (A-Z)", value=True)
                use_lower = st.checkbox("Lowercase (a-z)", value=True)
            with col_g2:
                use_digits = st.checkbox("Digits (0-9)", value=True)
                use_symbols = st.checkbox("Symbols (!@#$)", value=True)

            if st.button("Generate Now", key="btn_do_generate"):
                generated = generate_password(
                    gen_len, use_upper, use_lower, use_digits, use_symbols)
                st.session_state.gen_pwd_val = generated

            if "gen_pwd_val" in st.session_state:
                st.code(st.session_state.gen_pwd_val, language="text")
                if st.button("Use Generated Password"):
                    st.session_state.new_cred_pwd = st.session_state.gen_pwd_val

        col_in1, col_in2 = st.columns(2)
        with col_in1:
            site = st.text_input(
                "Service / Website URL", placeholder="e.g. github.com", key="new_cred_site").strip()
            username = st.text_input(
                "Username or Email", placeholder="e.g. alice@example.com", key="new_cred_user").strip()
        with col_in2:
            default_pwd = st.session_state.get("new_cred_pwd", "")
            pwd_input = st.text_input(
                "Password",
                value=default_pwd,
                type="password",
                placeholder="Enter or generate a password",
                key="new_cred_pass_input",
            )
            # Live strength evaluation
            if pwd_input:
                score, label, tip = evaluate_password_strength(pwd_input)
                st.progress(score / 100)
                st.caption(f"**Strength:** {label} ({score}%) — {tip}")

            notes = st.text_input(
                "Notes (Optional)", placeholder="e.g. Recovery codes or PIN", key="new_cred_notes").strip()

        if st.button("Encrypt & Store Credential 💾", type="primary", key="btn_save_cred"):
            if not site or not username or not pwd_input:
                st.error("Site, username, and password are required.")
            else:
                try:
                    new_entry = Credential(
                        site=site, username=username, password=pwd_input, notes=notes)
                    credentials.append(new_entry)
                    store.write_credentials(user, vault_key, credentials)
                    store.save_user(st.session_state.username, user)
                    st.success(
                        f"Encrypted and stored credential for '{site}' successfully!")
                    st.session_state.pop("new_cred_pwd", None)
                    st.session_state.pop("gen_pwd_val", None)
                    st.session_state.pop("new_cred_pass_input", None)
                    st.rerun()
                except Exception:
                    st.error("Failed to save credential securely.")

    # -----------------------------------------------------------------
    # SECTION: SAVED CREDENTIALS LIST & MANAGEMENT
    # -----------------------------------------------------------------
    st.subheader("📋 Saved Credentials")

    if not credentials:
        st.info("Your vault is empty. Click 'Add New Credential' above to get started.")
    else:
        # Search / filter bar
        search_query = st.text_input(
            "🔍 Search credentials by site or username", "").strip().lower()
        filtered = [
            c for c in credentials
            if not search_query or search_query in c.site.lower() or search_query in c.username.lower()
        ]

        if not filtered:
            st.warning(f"No credentials match '{search_query}'.")

        for entry in filtered:
            with st.container(border=True):
                col_head1, col_head2 = st.columns([3, 1])
                with col_head1:
                    st.markdown(f"### 🌐 **{entry.site}**")
                    st.caption(
                        f"ID: `{entry.id[:8]}...` | Last Updated: `{entry.updated_at[:19]}`")
                with col_head2:
                    st.caption("🔒 AES-256-GCM")

                col_row1, col_row2, col_row3 = st.columns([2, 3, 2])
                with col_row1:
                    st.write(f"**Username:** `{entry.username}`")
                    if entry.notes:
                        st.caption(f"**Notes:** {entry.notes}")

                with col_row2:
                    show_pwd = st.checkbox(
                        "Show Password", key=f"toggle_{entry.id}")
                    if show_pwd:
                        st.code(entry.password, language="text")
                    else:
                        st.code("••••••••••••••••", language="text")

                with col_row3:
                    btn_edit_col, btn_del_col = st.columns(2)
                    with btn_del_col:
                        if st.button("🗑️ Delete", key=f"del_{entry.id}", type="secondary"):
                            credentials = [
                                c for c in credentials if c.id != entry.id]
                            store.write_credentials(
                                user, vault_key, credentials)
                            store.save_user(st.session_state.username, user)
                            st.rerun()
                    with btn_edit_col:
                        if st.button("✏️ Edit", key=f"edit_btn_{entry.id}"):
                            st.session_state[f"editing_{entry.id}"] = not st.session_state.get(
                                f"editing_{entry.id}", False)

                # In-place edit expander
                if st.session_state.get(f"editing_{entry.id}", False):
                    st.divider()
                    st.write("**Edit Credential:**")
                    edit_site = st.text_input(
                        "Site", value=entry.site, key=f"edit_site_{entry.id}").strip()
                    edit_user = st.text_input(
                        "Username", value=entry.username, key=f"edit_user_{entry.id}").strip()
                    edit_pwd = st.text_input(
                        "Password", value=entry.password, type="password", key=f"edit_pwd_{entry.id}")
                    edit_notes = st.text_input(
                        "Notes", value=entry.notes, key=f"edit_notes_{entry.id}").strip()

                    if st.button("Save Changes", key=f"save_edit_{entry.id}", type="primary"):
                        if not edit_site or not edit_user or not edit_pwd:
                            st.error(
                                "Site, username, and password cannot be empty.")
                        else:
                            entry.update(edit_site, edit_user,
                                         edit_pwd, edit_notes)
                            store.write_credentials(
                                user, vault_key, credentials)
                            store.save_user(st.session_state.username, user)
                            st.session_state[f"editing_{entry.id}"] = False
                            st.success("Credential updated.")
                            st.rerun()
