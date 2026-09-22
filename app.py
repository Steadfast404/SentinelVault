from __future__ import annotations

import streamlit as st

from auth.session import check_inactivity_timeout, cleanup_session_state
from ui.backup_page import render as render_backup
from ui.dashboard_page import render as render_dashboard
from ui.login_page import render as render_login
from ui.share_page import render as render_share
from vault.store import VaultStore

# Configure page layout and title
st.set_page_config(
    page_title="SentinelVault | Defense-in-Depth Vault",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

store = VaultStore()

# Ensure authentication state exists
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""

# Enforce session inactivity timeout (auto-lock after 5 minutes)
if check_inactivity_timeout(st.session_state):
    st.rerun()

# Render login / registration / recovery if not authenticated
if not st.session_state.authenticated:
    render_login(store)
    st.stop()

# -------------------------------------------------------------
# AUTHENTICATED APPLICATION SHELL
# -------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ SentinelVault")
    st.caption("Defense-in-Depth Password Manager")

    st.success(
        f"👤 Signed in as **{st.session_state.get('username', 'User')}**")

    # Defense badges reflecting AEAD and modern primitives
    st.markdown(
        """
        <div style='background-color: #1e293b; padding: 10px; border-radius: 8px; font-size: 0.85em; color: #94a3b8;'>
            <b>Active Defenses:</b><br/>
            • 🔐 <b>bcrypt</b> Master Auth (WF=12)<br/>
            • ⏱️ <b>TOTP</b> 2FA + Replay Defense<br/>
            • 🔒 <b>AES-256-GCM</b> AEAD At Rest<br/>
            • 🖼️ <b>LSB Stego</b> Covert Concealment<br/>
            • ✍️ <b>RSA-PSS + OAEP</b> PGP Sharing
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write("")

    page = st.radio(
        "Navigation",
        [
            "📋 Vault Dashboard",
            "🖼️ Stego Backups",
            "🤝 PGP Secure Sharing",
            "📖 Security Architecture",
        ],
        index=0,
    )

    st.divider()
    if st.button("🔒 Lock Vault & Logout", type="secondary", use_container_width=True):
        # Centralized purge of all sensitive keys and widget buffers
        cleanup_session_state(st.session_state)
        st.rerun()

# Page routing
if page == "📋 Vault Dashboard":
    render_dashboard(store)
elif page == "🖼️ Stego Backups":
    render_backup(store)
elif page == "🤝 PGP Secure Sharing":
    render_share(store)
elif page == "📖 Security Architecture":
    st.header("📖 SentinelVault Defense-in-Depth Architecture")
    st.markdown(
        """
        ### Multi-Layered Threat Model (CSE 4174 Cyber Security Lab)

        SentinelVault addresses the critical vulnerability of password managers: single-point failure.
        By layering five independent security primitives, breaking any single layer is never sufficient to compromise user credentials.

        | Layer | Mechanism | Defends Against | Lab Origin |
        |---|---|---|---|
        | **1. Authentication** | Salted `bcrypt` Hash (Work Factor = 12) | Stolen hash database, rainbow tables, GPU cracking | Lab 4 |
        | **2. Second Factor** | `pyotp` RFC 6238 TOTP (30s window + replay defense) | Stolen or guessed master password | Lab 3 |
        | **3. At-Rest Encryption** | `AES-256-GCM` AEAD + `PBKDF2-HMAC-SHA256` (600,000 rounds) | Direct disk access, physical storage theft, ciphertext tampering | Lab 4 |
        | **4. Covert Storage** | LSB Steganography in RGB PNGs (`Pillow`) | Targeted discovery and interception of backup files | Lab 5 |
        | **5. Multi-User Sharing** | Hybrid PGP (`RSA-2048-OAEP` + `AES-256-GCM` + `RSA-PSS` sign) | Interception, man-in-the-middle, or impersonation during sharing | Lab 6 |

        ---
        #### Cryptographic Boundaries
        ```
        Master Password ──(PBKDF2 600k + Domain Separation)──> Ephemeral 256-bit AES Keys
               │
               ▼ (bcrypt Work Factor 12)
        Stored Hash on Disk (Never Plaintext)

        Vault Disk File: [Random Nonce (12B)] + [AES-256-GCM Ciphertext + 16B Tag]
               │ (Authenticated Additional Data: Version + Username)
               ▼ (Optional LSB Steganography Concealment)
        Ordinary Looking PNG Cover Image
               │
               ▼ (Hybrid PGP: Encrypt Key with Recipient RSA-OAEP + Sign with Sender RSA-PSS)
        Secure Sharing Channel
        ```
        """
    )
