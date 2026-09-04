"""Encryption-at-rest for DAST target credentials.

Target auth passwords are encrypted with a Fernet key taken from the
``SCP_SECRET_KEY`` environment variable (a ``cryptography`` Fernet key or any
short string, which is stretched via a SHA-256 derived key so operators can
set a passphrase). The key is read at call time, like the auth middleware, so
tests can toggle it per-test and the service can be reconfigured by restart.

Persisted values are prefixed ``enc:v1:`` so decryption is self-describing and
legacy plaintext values still load (with a warning path left to the operator).
Storing a *new* plaintext password without a configured key fails closed.
"""

from __future__ import annotations

import os

from src.config import ConfigurationError

_PREFIX = "enc:v1:"


def _fernet():
    from cryptography.fernet import Fernet

    raw = os.getenv("SCP_SECRET_KEY", "")
    if not raw:
        return None
    if raw.startswith("gAAA") and len(raw) >= 100:
        return Fernet(raw.encode())
    # Use a deliberately expensive password KDF; a single SHA-256 is not a
    # password derivation function and permits cheap offline guessing.
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b"secure-development-tools/secretbox/v2",
                     iterations=600_000)
    return Fernet(base64_urlsafe(kdf.derive(raw.encode("utf-8"))))


def base64_urlsafe(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").strip()


def encrypt_secret(plain: str) -> str:
    """Encrypt a secret for persistence. Fails closed without SCP_SECRET_KEY."""
    if not plain:
        return ""
    f = _fernet()
    if f is None:
        raise ConfigurationError(
            "cannot store DAST credentials: set SCP_SECRET_KEY (Fernet key or "
            "passphrase) to enable encryption at rest"
        )
    return _PREFIX + f.encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    """Decrypt a persisted secret; legacy plaintext is deliberately unusable."""
    if not value or not value.startswith(_PREFIX):
        # Never return historical plaintext credentials. Operators must rotate
        # or explicitly re-enter them; this prevents accidental re-use.
        return ""
    f = _fernet()
    if f is None:
        # Key was rotated away; never guess — treat as unavailable.
        return ""
    try:
        return f.decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:  # noqa: BLE001 - wrong key / corrupted token -> empty
        return ""


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_PREFIX)
