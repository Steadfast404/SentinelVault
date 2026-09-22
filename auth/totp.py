from __future__ import annotations

from io import BytesIO
import time
from typing import Tuple

import pyotp
import qrcode


def generate_secret() -> str:
    """Generate a random Base32 TOTP secret string."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SentinelVault") -> str:
    """Generate standard otpauth URI for mobile authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_image(uri: str) -> bytes:
    """Generate PNG bytes of the QR code corresponding to the TOTP URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=3,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def verify_code(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code against the secret.
    Valid window is set to 1 (current step +/- 30s) to tolerate slight clock drift.
    """
    if not code or not secret:
        return False
    clean_code = code.strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    try:
        totp = pyotp.TOTP(secret)
        return bool(totp.verify(clean_code, valid_window=1))
    except Exception:
        return False


def verify_code_with_replay_prevention(
    secret: str,
    code: str,
    last_verified_timestep: int = 0,
) -> Tuple[bool, int]:
    """
    Verify a 6-digit TOTP code and prevent replay attacks.
    Ensures that a code cannot be reused within the same 30-second window.
    Returns (is_valid, new_verified_timestep).
    """
    if not code or not secret:
        return False, last_verified_timestep
    clean_code = code.strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False, last_verified_timestep

    try:
        totp = pyotp.TOTP(secret)
        now_step = int(time.time() / 30)

        # Check adjacent steps [-1, 0, 1]
        for offset in (0, -1, 1):
            target_step = now_step + offset
            if target_step <= last_verified_timestep:
                # Already used in this or a later time step! Replay rejected.
                continue

            expected = totp.generate_otp(target_step)
            if clean_code == expected:
                return True, target_step

        return False, last_verified_timestep
    except Exception:
        return False, last_verified_timestep


def get_current_code_for_testing(secret: str) -> str:
    """Helper restricted to automated test verification only."""
    return pyotp.TOTP(secret).now()
