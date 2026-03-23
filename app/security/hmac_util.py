"""Port server1/src/security/hmac.js"""
from __future__ import annotations

import hashlib
import hmac


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_hmac_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def safe_equal_hex(a: str, b: str) -> bool:
    try:
        aa = bytes.fromhex(a)
        bb = bytes.fromhex(b)
    except ValueError:
        return False
    if len(aa) != len(bb):
        return False
    return hmac.compare_digest(aa, bb)
