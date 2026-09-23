from __future__ import annotations

import os
import shutil
import unittest
from streamlit.testing.v1 import AppTest
from vault.store import VaultStore
import pyotp


class TestFrontendStreamlitFlow(unittest.TestCase):
    def setUp(self) -> None:
        self.username = "test_ui_runner"
        self.password = "StrongPassword2026!"
        self.store = VaultStore()
        # Clean up any leftover file
        p = self.store.user_path(self.username)
        if p.exists():
            p.unlink()

    def tearDown(self) -> None:
        p = self.store.user_path(self.username)
        if p.exists():
            p.unlink()

    def test_complete_frontend_ui_lifecycle(self) -> None:
        """Test full registration, TOTP enrollment, login, dashboard, backup, and logout via AppTest."""
        app_path = os.path.abspath("app.py")
        at = AppTest.from_file(app_path, default_timeout=30)
        at.run()

        self.assertFalse(at.exception)
        self.assertEqual(len(at.tabs), 3)

        # 1. Register new user
        at.tabs[1].text_input(key="reg_user").input(self.username)
        at.tabs[1].text_input(key="reg_pass").input(self.password)
        at.tabs[1].text_input(key="reg_confirm").input(self.password)
        at.tabs[1].button(key="btn_create_user").click().run()

        self.assertFalse(at.exception)
        reg_info = at.session_state.get("new_registration")
        self.assertIsNotNone(reg_info)
        totp_secret = reg_info["secret"]

        # Confirm TOTP saved
        at.button(key="btn_confirm_totp_saved").click().run()
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state.get("login_stage"), "password")

        # 2. Login Step 1 (Password)
        at.text_input(key="login_user_input").input(self.username)
        at.text_input(key="login_pass_input").input(self.password)
        at.button(key="btn_check_password").click().run()

        self.assertFalse(at.exception)
        self.assertEqual(at.session_state.get("login_stage"), "otp")

        # 3. Login Step 2 (TOTP)
        code = pyotp.TOTP(totp_secret).now()
        at.text_input(key="login_otp_input").input(code)
        at.button(key="btn_verify_otp").click().run()

        self.assertFalse(at.exception)
        self.assertTrue(at.session_state.get("authenticated"))
        self.assertEqual(at.session_state.get("username"), self.username)

        # 4. Add Credential in Dashboard
        at.text_input(key="new_cred_site").input("github.com")
        at.text_input(key="new_cred_user").input("dev@example.com")
        at.text_input(key="new_cred_pass_input").input("GeneratedPass123!")
        at.button(key="btn_save_cred").click().run()

        self.assertFalse(at.exception)

        # 5. Navigate to PGP Secure Sharing
        at.sidebar.radio[0].set_value("🤝 PGP Secure Sharing").run()
        self.assertFalse(at.exception)
        self.assertEqual(len(at.tabs), 3)

        # 6. Navigate to Stego Backups
        at.sidebar.radio[0].set_value("🖼️ Stego Backups").run()
        self.assertFalse(at.exception)
        self.assertEqual(len(at.tabs), 2)

        # 7. Logout
        logout_btn = [b for b in at.sidebar.button if "Logout" in b.label][0]
        logout_btn.click().run()
        self.assertFalse(at.exception)
        self.assertFalse(at.session_state.get("authenticated"))
