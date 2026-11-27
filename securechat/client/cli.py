"""CLI:  python -m securechat.client --user alice [comando]

Comandos: register | send <a> <texto> | inbox | contacts | safety <a> | verify <a> | history
Sin comando se abre un menú interactivo.
Para pruebas automáticas se leen SECURECHAT_PASSWORD y SECURECHAT_PASSPHRASE (NO las guarde en el repo).
"""
import argparse
import getpass
import os
import sys
from datetime import datetime

from .api import ApiError
from .core import ChatClient, IdentityChangedError

WIDTH = 60


# ----------------------------------------------------------------- presentación
def banner(user: str, server: str) -> None:
    print("=" * WIDTH)
    print("SECURECHAT - Mensajería cifrada de extremo a extremo".center(WIDTH))
    print("X3DH + Double Ratchet".center(WIDTH))
    print("=" * WIDTH)
    print(f"  Usuario : {user}")
    print(f"  Servidor: {server}")
    print("=" * WIDTH)


def title(text: str) -> None:
    print()
    print("-" * WIDTH)
    print(f"  {text}")
    print("-" * WIDTH)


def ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def info(msg: str) -> None:
    print(f"  {msg}")


def err(msg: str) -> None:
    print(f"  [ERROR] {msg}", file=sys.stderr)


def _secret(env: str, prompt: str) -> str:
    return os.getenv(env) or getpass.getpass(f"  {prompt}")


# ----------------------------------------------------------------- acciones
class Session:
    """Envuelve ChatClient y recuerda si ya se hizo login (para el menú interactivo)."""

    def __init__(self, client: ChatClient):
        self.c = client
        self.logged_in = False

    def ensure_login(self) -> None:
        if not self.logged_in:
            self.c.login(_secret("SECURECHAT_PASSWORD", "Contraseña del servidor: "))
            self.logged_in = True
            ok("Sesión iniciada.")

    def register(self) -> None:
        title("REGISTRO DE USUARIO")
        self.c.register(_secret("SECURECHAT_PASSWORD", "Contraseña del servidor (mín. 10 caracteres): "))
        ok("Registrado. Claves generadas y guardadas cifradas en el almacén local.")

    def send(self, to: str, text: str) -> None:
        title(f"ENVIAR MENSAJE A: {to}")
        self.ensure_login()
        n = self.c.send(to, text)
        ok(f"Enviado (mensaje #{n}).")

    def inbox(self) -> None:
        title("BANDEJA DE ENTRADA")
        self.ensure_login()
        msgs = self.c.receive()
        if not msgs:
            info("No hay mensajes nuevos.")
        for r in msgs:
            if r.text is not None:
                info(f"[{r.sender} #{r.n}] {r.text}")
            else:
                info(f"[RECHAZADO de {r.sender} #{r.n}] {r.error}")

    def contacts(self) -> None:
        title("CONTACTOS")
        items = self.c.contacts()
        if not items:
            info("Aún no tiene contactos.")
        for name, data in items.items():
            info(f"{name:<20} {'VERIFICADO' if data['verified'] else 'no verificado'}")

    def safety(self, peer: str) -> None:
        title(f"SAFETY NUMBER CON: {peer}")
        info(self.c.safety_number(peer))
        info("Compare este número con el que ve su contacto por un canal confiable.")

    def verify(self, peer: str) -> None:
        title(f"VERIFICAR CONTACTO: {peer}")
        info(f"Safety number: {self.c.safety_number(peer)}")
        if input("  ¿Coincide con el que ve su contacto? [s/N] ").strip().lower() == "s":
            self.c.mark_verified(peer)
            ok("Contacto marcado como verificado.")
        else:
            info("Contacto NO verificado.")

    def history(self) -> None:
        title("HISTORIAL DE MENSAJES")
        hist = self.c.store.data["history"]
        if not hist:
            info("El historial está vacío.")
        for h in hist:
            info(f"{datetime.fromtimestamp(h['ts']):%H:%M:%S} {h['dir']} {h['peer']}: {h['text']}")


# ----------------------------------------------------------------- menú interactivo
MENU = [
    ("1", "Registrarse"),
    ("2", "Enviar mensaje"),
    ("3", "Ver bandeja de entrada"),
    ("4", "Ver contactos"),
    ("5", "Ver safety number"),
    ("6", "Verificar contacto"),
    ("7", "Ver historial"),
    ("0", "Salir"),
]


def _ask(prompt: str) -> str:
    value = ""
    while not value:
        value = input(f"  {prompt}").strip()
    return value


def interactive(s: Session) -> int:
    while True:
        title("MENÚ PRINCIPAL")
        for key, label in MENU:
            info(f"[{key}] {label}")
        choice = input("\n  Elija una opción: ").strip()
        try:
            if choice == "1":
                s.register()
            elif choice == "2":
                s.send(_ask("Destinatario: "), _ask("Mensaje: "))
            elif choice == "3":
                s.inbox()
            elif choice == "4":
                s.contacts()
            elif choice == "5":
                s.safety(_ask("Contacto: "))
            elif choice == "6":
                s.verify(_ask("Contacto: "))
            elif choice == "7":
                s.history()
            elif choice == "0":
                title("HASTA LUEGO")
                return 0
            else:
                err("Opción no válida.")
        except IdentityChangedError as e:
            err(str(e))
        except ApiError as e:
            err(f"Error del servidor: {e}")
            if choice in ("2", "3"):
                s.logged_in = False


# ----------------------------------------------------------------- entrada
def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securechat", description="Cliente de SecureChat (sin comando abre el menú).")
    p.add_argument("--server", default=os.getenv("SECURECHAT_SERVER", "http://127.0.0.1:8000"))
    p.add_argument("--user", required=True)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("register", help="registrar el usuario y generar claves")
    s = sub.add_parser("send", help="enviar un mensaje"); s.add_argument("to"); s.add_argument("text", nargs="+")
    sub.add_parser("inbox", help="leer mensajes nuevos")
    sub.add_parser("contacts", help="listar contactos")
    sub.add_parser("safety", help="mostrar safety number").add_argument("peer")
    sub.add_parser("verify", help="verificar un contacto").add_argument("peer")
    sub.add_parser("history", help="ver historial local")
    a = p.parse_args(argv)

    banner(a.user, a.server)
    passphrase = _secret("SECURECHAT_PASSPHRASE", "Frase local (protege sus claves privadas): ")
    sess = Session(ChatClient(a.server, a.user, passphrase))

    if a.cmd is None:
        try:
            return interactive(sess)
        except (KeyboardInterrupt, EOFError):
            print()
            return 0

    try:
        if a.cmd == "register":
            sess.register()
        elif a.cmd == "send":
            sess.send(a.to, " ".join(a.text))
        elif a.cmd == "inbox":
            sess.inbox()
        elif a.cmd == "contacts":
            sess.contacts()
        elif a.cmd == "safety":
            sess.safety(a.peer)
        elif a.cmd == "verify":
            sess.verify(a.peer)
        elif a.cmd == "history":
            sess.history()
    except IdentityChangedError as e:
        err(str(e)); return 2
    except ApiError as e:
        err(f"Error del servidor: {e}"); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
