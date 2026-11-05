"""Utilitários criptográficos: HMAC, derivação de chaves e criptografia reversível."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_FERNET_SALT = b"anonapp/fernet/v1"
_PBKDF2_ITERATIONS = 200_000


def generate_secret(nbytes: int = 32) -> str:
    """Gera uma chave secreta aleatória (URL-safe)."""
    return secrets.token_urlsafe(nbytes)


def hmac_digest(key: str, message: str) -> bytes:
    """HMAC-SHA256 da mensagem com a chave secreta."""
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()


def hmac_hex(key: str, message: str) -> str:
    return hmac_digest(key, message).hex()


def hmac_int(key: str, message: str) -> int:
    """Inteiro de 64 bits derivado de forma determinística via HMAC."""
    return int.from_bytes(hmac_digest(key, message)[:8], "big")


def hmac_stream(key: str, message: str, length: int) -> bytes:
    """Fluxo pseudoaleatório determinístico com `length` bytes."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac_digest(key, f"{message}|{counter}")
        counter += 1
    return out[:length]


def key_fingerprint(key: str) -> str:
    """Impressão digital da chave. Permite conferir a chave sem expô-la."""
    return hmac_hex(key, "anonapp/fingerprint")[:16]


def _fernet(key: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_FERNET_SALT,
        iterations=_PBKDF2_ITERATIONS,
    )
    derived = kdf.derive(key.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


class Cipher:
    """Criptografia autenticada (AES-128-CBC + HMAC-SHA256, padrão Fernet)."""

    def __init__(self, key: str):
        self._f = _fernet(key)

    def encrypt(self, value: str) -> str:
        return self._f.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str | None:
        try:
            return self._f.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError):
            return None
