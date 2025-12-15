import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_key() -> bytes:
    b64 = os.environ.get("MOBYPARK_AES_KEY")
    if not b64:
        raise RuntimeError("MOBYPARK_AES_KEY not set. Provide base64-encoded 32-byte key.")
    try:
        key = base64.b64decode(b64)
    except Exception:
        raise RuntimeError("MOBYPARK_AES_KEY is not valid base64")
    if len(key) not in (16, 24, 32):
        raise RuntimeError("Invalid AES key length. Use 16/24/32 bytes (base64-encoded).")
    return key


def encrypt_str(plaintext: str, associated_data: Optional[bytes] = None) -> str:
    if plaintext is None:
        return None
    key = _load_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    payload = nonce + ct
    return base64.b64encode(payload).decode("ascii")


def decrypt_str(b64payload: str, associated_data: Optional[bytes] = None) -> str:
    if b64payload is None:
        return None
    key = _load_key()
    aesgcm = AESGCM(key)
    try:
        data = base64.b64decode(b64payload)
    except Exception:
        raise ValueError("Payload is not valid base64-encoded encrypted data")
    if len(data) < 13:
        raise ValueError("Payload is too short to be valid encrypted data")
    nonce = data[:12]
    ct = data[12:]
    pt = aesgcm.decrypt(nonce, ct, associated_data)
    return pt.decode("utf-8")


def mask_value(value: str, keep: int = 1) -> str:
    if value is None:
        return None
    if len(value) <= keep + 1:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)
