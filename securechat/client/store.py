"""Almacén local cifrado (Argon2id + AES-256-GCM). Guarda claves privadas, sesiones, contactos e historial.

Ubicación: $SECURECHAT_HOME/<usuario>.enc  (por defecto ~/.securechat). NUNCA se sube al repositorio.
"""
import os
import time
from pathlib import Path

from securechat.crypto.aead import open_json, seal_json


def home_dir() -> Path:
    d = Path(os.getenv("SECURECHAT_HOME", Path.home() / ".securechat"))
    d.mkdir(parents=True, exist_ok=True)
    return d


class LocalStore:
    def __init__(self, username: str, passphrase: str):
        self.path = home_dir() / f"{username}.enc"
        self.passphrase = passphrase
        self.data = {"keys": None, "contacts": {}, "sessions": {}, "history": []}
        if self.path.exists():
            # InvalidTag aquí significa frase incorrecta o archivo alterado
            self.data = open_json(passphrase, self.path.read_bytes())

    def exists(self) -> bool:
        return self.path.exists()

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(seal_json(self.passphrase, self.data))
        tmp.replace(self.path)

    def add_history(self, peer: str, direction: str, n: int, text: str) -> None:
        self.data["history"].append({"peer": peer, "dir": direction, "n": n, "text": text, "ts": time.time()})
