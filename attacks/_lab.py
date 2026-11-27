"""Laboratorio reproducible para los ataques y las pruebas E2E (PARTE 4).

Levanta un servidor real en localhost con una base de datos temporal y crea clientes con
credenciales aleatorias generadas en cada ejecución (nada de secretos fijos en el repositorio).
"""
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from securechat.client.core import ChatClient  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Lab:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "server.db")
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.secrets: dict[str, tuple[str, str]] = {}  # usuario -> (contraseña, frase local)
        self.proc = None

    def __enter__(self):
        env = dict(os.environ, SECURECHAT_DB=self.db, PORT=str(self.port),
                   SECURECHAT_HOME=os.path.join(self.tmp.name, "clients"), PYTHONPATH=str(ROOT))
        os.environ["SECURECHAT_HOME"] = env["SECURECHAT_HOME"]
        self.proc = subprocess.Popen([sys.executable, "-m", "securechat.server"], cwd=ROOT, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if requests.get(self.url + "/health", timeout=0.5).ok:
                    return self
            except requests.RequestException:
                time.sleep(0.1)
        raise RuntimeError("el servidor de laboratorio no arrancó")

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.tmp.cleanup()

    def client(self, name: str, register: bool = True) -> ChatClient:
        pw, phrase = self.secrets.setdefault(name, (secrets.token_urlsafe(16), secrets.token_urlsafe(16)))
        c = ChatClient(self.url, name, phrase)
        if register:
            c.register(pw)
        c.login(pw)
        return c

    def db_execute(self, sql: str, params=()):
        """Simula a un operador malicioso con acceso directo a la base de datos del servidor."""
        with sqlite3.connect(self.db) as conn:
            return conn.execute(sql, params).fetchall()


def verdict(defended: bool, ok_msg: str, fail_msg: str) -> int:
    print(("  [DEFENSA OK] " + ok_msg) if defended else ("  [FALLO DE SEGURIDAD] " + fail_msg))
    return 0 if defended else 1
