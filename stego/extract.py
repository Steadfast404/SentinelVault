from __future__ import annotations

from io import BytesIO

from PIL import Image

from stego.embed import HEADER_LEN, MAGIC, MAX_PAYLOAD_SIZE

# Security limit: Prevent decompression bomb attacks
Image.MAX_IMAGE_PIXELS = 10_000_000


def extract_bytes(image_bytes: bytes) -> bytes:
    """
    Extract embedded payload from the LSBs of a PNG image.
    Verifies the SentinelVault magic header and extracts payload by length.
    """
    try:
        image = Image.open(BytesIO(image_bytes))
        if image.format != "PNG":
            raise ValueError("File is not a valid PNG image.")
        converted = image.convert("RGB")
    except Exception as exc:
        raise ValueError(f"Failed to read image: {exc}") from exc

    raw = converted.tobytes()
    header_bits_needed = HEADER_LEN * 8

    if len(raw) < header_bits_needed:
        raise ValueError(
            "Image is too small to contain a SentinelVault payload.")

    # Read header bytes
    header_bytes = bytearray()
    for byte_i in range(HEADER_LEN):
        val = 0
        offset = byte_i * 8
        for bit_i in range(8):
            val = (val << 1) | (raw[offset + bit_i] & 1)
        header_bytes.append(val)

    if not header_bytes.startswith(MAGIC):
        raise ValueError(
            "No SentinelVault steganographic payload detected in this image.")

    size_start = len(MAGIC)
    payload_size = int.from_bytes(
        header_bytes[size_start: size_start + 4], "big")

    if payload_size <= 0 or payload_size > MAX_PAYLOAD_SIZE:
        raise ValueError(
            "Steganographic payload has an invalid or excessive size.")

    start_bit = header_bits_needed
    end_bit = start_bit + payload_size * 8

    if end_bit > len(raw):
        raise ValueError(
            "Steganographic payload is truncated or image has been modified.")

    # Extract payload bytes
    payload = bytearray(payload_size)
    for byte_i in range(payload_size):
        val = 0
        offset = start_bit + byte_i * 8
        for bit_i in range(8):
            val = (val << 1) | (raw[offset + bit_i] & 1)
        payload[byte_i] = val

    return bytes(payload)
