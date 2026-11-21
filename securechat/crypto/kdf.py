"""Derivación de claves: HKDF-SHA256 [RFC 5869] y Argon2id [RFC 9106].

Tabla de parámetros del documento E1:
  Argon2id: m = 64 MiB, t = 3, p = 4, sal de 16 bytes, salida de 32 bytes.
"""
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB (el parámetro de la biblioteca está en KiB)
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
SALT_LEN = 16


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    """HKDF-SHA256. `info` siempre debe llevar una etiqueta de contexto (separación de dominios)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def argon2id(secret: bytes, salt: bytes, length: int = 32) -> bytes:
    """Deriva `length` bytes a partir de un secreto de baja entropía (contraseña / frase)."""
    return Argon2id(
        salt=salt,
        length=length,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    ).derive(secret)


def hash_password(password: str) -> tuple[bytes, bytes]:
    """Devuelve (sal, hash). Es lo único que el servidor guarda de la contraseña."""
    salt = new_salt()
    return salt, argon2id(password.encode("utf-8"), salt)


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    candidate = argon2id(password.encode("utf-8"), salt)
    return hmac.compare_digest(candidate, expected)  # comparación en tiempo constante
