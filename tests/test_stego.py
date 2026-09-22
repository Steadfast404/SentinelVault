from __future__ import annotations

import unittest

from PIL import Image
from io import BytesIO

from stego.embed import create_sample_cover_image, embed_bytes, get_image_capacity
from stego.extract import extract_bytes


class TestSteganography(unittest.TestCase):
    def setUp(self) -> None:
        self.cover_bytes = create_sample_cover_image(200, 200)

    def test_capacity_calculation(self) -> None:
        capacity, (w, h) = get_image_capacity(self.cover_bytes)
        self.assertEqual(w, 200)
        self.assertEqual(h, 200)
        # 200 * 200 * 3 = 120,000 bits = 15,000 bytes - 18 = 14,982 bytes
        self.assertEqual(capacity, 14982)

    def test_embed_and_extract_roundtrip(self) -> None:
        payload = b'{"vault_salt": "abcdef123456", "vault": {"iv": "123", "ciphertext": "abc"}}'
        stego_png = embed_bytes(self.cover_bytes, payload)

        # Output must be a valid PNG
        self.assertTrue(stego_png.startswith(b"\x89PNG\r\n\x1a\n"))

        # Extracted bytes must exactly match original
        extracted = extract_bytes(stego_png)
        self.assertEqual(extracted, payload)

    def test_reject_ordinary_image(self) -> None:
        # An image without SentinelVault header must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            extract_bytes(self.cover_bytes)
        self.assertIn(
            "No SentinelVault steganographic payload detected", str(ctx.exception))

    def test_reject_payload_exceeding_capacity(self) -> None:
        # 200x200 holds ~14.9 KB; try to embed 20 KB
        huge_payload = b"A" * 20000
        with self.assertRaises(ValueError) as ctx:
            embed_bytes(self.cover_bytes, huge_payload)
        self.assertIn("Cover image is too small", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
