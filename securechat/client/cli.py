"""CLI:  python -m securechat.client --user alice <comando>

Comandos: register | send <a> <texto> | inbox | contacts | safety <a> | verify <a> | history
Para pruebas automáticas se leen SECURECHAT_PASSWORD y SECURECHAT_PASSPHRASE (NO las guarde en el repo).
"""
import argparse
import getpass
import os
import sys
from datetime import datetime

from .api import ApiError
from .core import ChatClient, IdentityChangedError


def _secret(env: str, prompt: str) -> str:
    return os.getenv(env) or getpass.getpass(prompt)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securechat")
    p.add_argument("--server", default=os.getenv("SECURECHAT_SERVER", "http://127.0.0.1:8000"))
    p.add_argument("--user", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("register")
    s = sub.add_parser("send"); s.add_argument("to"); s.add_argument("text", nargs="+")
    sub.add_parser("inbox")
    sub.add_parser("contacts")
    for name in ("safety", "verify"):
        sub.add_parser(name).add_argument("peer")
    sub.add_parser("history")
    a = p.parse_args(argv)

    passphrase = _secret("SECURECHAT_PASSPHRASE", "Frase local (protege sus claves privadas): ")
    c = ChatClient(a.server, a.user, passphrase)
    try:
        if a.cmd == "register":
            c.register(_secret("SECURECHAT_PASSWORD", "Contraseña del servidor (mín. 10 caracteres): "))
            print("Registrado. Claves generadas y guardadas cifradas en el almacén local.")
            return 0
        if a.cmd in ("send", "inbox"):
            c.login(_secret("SECURECHAT_PASSWORD", "Contraseña del servidor: "))
        if a.cmd == "send":
            n = c.send(a.to, " ".join(a.text)); print(f"Enviado (mensaje #{n}).")
        elif a.cmd == "inbox":
            for r in c.receive():
                print(f"[{r.sender} #{r.n}] {r.text}" if r.text is not None else f"[RECHAZADO de {r.sender} #{r.n}] {r.error}")
        elif a.cmd == "contacts":
            for name, info in c.contacts().items():
                print(f"{name}: {'VERIFICADO' if info['verified'] else 'no verificado'}")
        elif a.cmd == "safety":
            print(c.safety_number(a.peer))
        elif a.cmd == "verify":
            print("Safety number:", c.safety_number(a.peer))
            if input("¿Coincide con el que ve su contacto? [s/N] ").lower() == "s":
                c.mark_verified(a.peer); print("Contacto marcado como verificado.")
        elif a.cmd == "history":
            for h in c.store.data["history"]:
                print(f"{datetime.fromtimestamp(h['ts']):%H:%M:%S} {h['dir']} {h['peer']}: {h['text']}")
    except IdentityChangedError as e:
        print(str(e), file=sys.stderr); return 2
    except ApiError as e:
        print(f"Error del servidor: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
