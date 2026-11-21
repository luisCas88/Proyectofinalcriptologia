"""Cifrado autenticado AES-256-GCM [NIST SP 800-38D].

Estrategia de nonces (unicidad por diseño):
  * Mensajes: cada clave de mensaje MK_i se usa UNA sola vez. De MK_i se derivan con HKDF
    la clave AEAD (32 bytes) y el nonce (12 bytes). Misma clave => nunca el mismo nonce.
  * Almacenamiento local: sal Argon2id nueva en cada guardado (=> clave nueva) y nonce aleatorio.
"""
import json
import os

from cryptography.exceptions import InvalidTag  # noqa: F401  (se reexporta para quien captura)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import argon2id, hkdf, new_salt

MSG_INFO = b"securechat/v1/message-key"


def _msg_key_nonce(message_key: bytes) -> tuple[bytes, bytes]:
    okm = hkdf(message_key, MSG_INFO, length=44)
    return okm[:32], okm[32:]


def encrypt_message(message_key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    key, nonce = _msg_key_nonce(message_key)
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt_message(message_key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Lanza cryptography.exceptions.InvalidTag si el texto cifrado o los AD fueron alterados."""
    key, nonce = _msg_key_nonce(message_key)
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


# ---- Almacenamiento local protegido con frase (Argon2id + AES-256-GCM) ----

STORE_AD = b"securechat/v1/local-store"


def seal_json(passphrase: str, data: dict) -> bytes:
    salt = new_salt()
    key = argon2id(passphrase.encode("utf-8"), salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), STORE_AD)
    return salt + nonce + ct


def open_json(passphrase: str, blob: bytes) -> dict:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = argon2id(passphrase.encode("utf-8"), salt)
    return json.loads(AESGCM(key).decrypt(nonce, ct, STORE_AD))
