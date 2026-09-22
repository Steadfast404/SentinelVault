from __future__ import annotations

from io import BytesIO
from typing import Tuple

from PIL import Image, ImageDraw

# Security limit: Prevent decompression bomb attacks
Image.MAX_IMAGE_PIXELS = 10_000_000

MAGIC = b"SENTINELVAULT\x00"
HEADER_LEN = len(MAGIC) + 4  # Magic bytes + 4 bytes big-endian length
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024  # 5 MB


def get_image_capacity(image_bytes: bytes) -> Tuple[int, Tuple[int, int]]:
    """
    Calculate maximum payload byte capacity for a given image.
    Returns (max_payload_bytes, (width, height)).
    """
    try:
        image = Image.open(BytesIO(image_bytes))
        if image.format != "PNG":
            raise ValueError(
                "Only PNG images are supported for lossless LSB steganography.")
        converted = image.convert("RGB")
    except Exception as exc:
        raise ValueError(f"Invalid image file: {exc}") from exc

    total_bits = converted.width * converted.height * 3
    total_bytes = total_bits // 8
    max_payload = max(0, total_bytes - HEADER_LEN)
    return min(max_payload, MAX_PAYLOAD_SIZE), converted.size


def create_sample_cover_image(width: int = 512, height: int = 512) -> bytes:
    """
    Generate an elegant gradient PNG cover image suitable for LSB steganography.
    Capacity: (512 * 512 * 3) / 8 - 18 = 98,286 bytes (~96 KB).
    """
    image = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(image)

    for y in range(height):
        ratio = y / height
        r = int(18 + ratio * 32)
        g = int(30 + ratio * 60)
        b = int(49 + ratio * 90)
        draw.line([(0, y), (width, y)], fill=(r, g, b))

    draw.rectangle([40, 40, width - 40, height - 40],
                   outline=(45, 85, 125), width=2)
    draw.line([40, 40, width - 40, height - 40], fill=(35, 70, 105), width=1)
    draw.line([40, height - 40, width - 40, 40], fill=(35, 70, 105), width=1)

    buf = BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def embed_bytes(image_bytes: bytes, payload: bytes) -> bytes:
    """
    Embed payload bytes into the least significant bits (LSBs) of RGB pixels.
    Format: [MAGIC (14 bytes)] + [Payload Length (4 bytes big-endian)] + [Payload Bytes].
    Note: Steganography provides covert concealment; data security relies on the payload's AEAD encryption.
    """
    if not payload:
        raise ValueError("Payload cannot be empty")
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError("Payload exceeds maximum allowed size (5 MB).")

    try:
        image = Image.open(BytesIO(image_bytes))
        if image.format != "PNG":
            raise ValueError(
                "Only PNG images are supported for lossless LSB steganography.")
        converted = image.convert("RGB")
    except Exception as exc:
        raise ValueError(f"Invalid cover image: {exc}") from exc

    raw = bytearray(converted.tobytes())

    message = MAGIC + len(payload).to_bytes(4, "big") + payload
    total_bits_needed = len(message) * 8

    if total_bits_needed > len(raw):
        max_bytes = (len(raw) // 8) - HEADER_LEN
        raise ValueError(
            f"Cover image is too small. Maximum capacity is {max_bytes:,} bytes, "
            f"but payload requires {len(payload):,} bytes."
        )

    bit_idx = 0
    for byte in message:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            bit = (byte >> shift) & 1
            raw[bit_idx] = (raw[bit_idx] & 0xFE) | bit
            bit_idx += 1

    encoded_image = Image.frombytes("RGB", converted.size, bytes(raw))
    output = BytesIO()
    encoded_image.save(output, format="PNG")
    return output.getvalue()
