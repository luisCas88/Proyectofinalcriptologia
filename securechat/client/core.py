"""Lógica del cliente: registro, contactos (TOFU + safety numbers), envío y recepción.

Reglas que NO se pueden saltar (criterios C2/C4 de la rúbrica):
  1. Toda clave pública ajena se verifica (firma del bundle) antes de usarse.
  2. Cambio de la clave de identidad de un contacto => IdentityChangedError (alerta visible).
  3. Un mensaje que no autentica (GCM) o es replay se rechaza y NO modifica el estado.
"""
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from securechat.crypto import x3dh
from securechat.crypto.encoding import b64d, b64e
from securechat.crypto.keys import BundleSignatureError, IdentityKeys, PreKeyBundle, verify_bundle
from securechat.crypto.ratchet import ReplayError, Session, TooManySkippedError
from securechat.crypto.safety import safety_number

from .api import Api
from .store import LocalStore


class IdentityChangedError(Exception):
    """La clave de identidad de un contacto cambió: posible MITM. Mostrar alerta al usuario."""


@dataclass
class Received:
    sender: str
    n: int
    text: str | None
    error: str | None = None  # si no es None, el mensaje fue rechazado


class ChatClient:
    def __init__(self, server_url: str, username: str, local_passphrase: str):
        self.username = username
        self.api = Api(server_url)
        self.store = LocalStore(username, local_passphrase)

    # ---------- cuenta ----------
    def register(self, password: str) -> None:
        if self.store.exists() and self.store.data["keys"]:
            raise RuntimeError("ya existe un almacén local para este usuario")
        keys = IdentityKeys.generate()
        self.api.register(self.username, password, keys.bundle().to_dict())
        self.store.data["keys"] = keys.to_dict()
        self.store.save()

    def login(self, password: str) -> None:
        self.api.login(self.username, password)

    @property
    def keys(self) -> IdentityKeys:
        return IdentityKeys.from_dict(self.store.data["keys"])

    # ---------- contactos: verificación + TOFU ----------
    def _fetch_verified_bundle(self, peer: str) -> PreKeyBundle:
        bundle = PreKeyBundle.from_dict(self.api.get_bundle(peer))
        verify_bundle(bundle)  # lanza BundleSignatureError (ataque: sustituir signed prekey)
        self._tofu(peer, bundle)
        return bundle

    def _tofu(self, peer: str, bundle: PreKeyBundle) -> None:
        known = self.store.data["contacts"].get(peer)
        sig, dh = b64e(bundle.ik_sig_pub), b64e(bundle.ik_dh_pub)
        if known is None:  # primera vez: se fija la identidad, queda "no verificada"
            self.store.data["contacts"][peer] = {"ik_sig_pub": sig, "ik_dh_pub": dh, "verified": False}
            self.store.save()
        elif known["ik_sig_pub"] != sig or known["ik_dh_pub"] != dh:
            raise IdentityChangedError(
                f"¡ALERTA! La identidad de '{peer}' cambió. Compare el safety number por un canal externo.")

    def refresh_contact(self, peer: str) -> PreKeyBundle:
        """Vuelve a pedir el bundle y comprueba que la identidad no cambió."""
        return self._fetch_verified_bundle(peer)

    def safety_number(self, peer: str) -> str:
        c = self.store.data["contacts"][peer]
        mine = self.keys.bundle()
        return safety_number(mine.ik_sig_pub, mine.ik_dh_pub, b64d(c["ik_sig_pub"]), b64d(c["ik_dh_pub"]))

    def mark_verified(self, peer: str) -> None:
        self.store.data["contacts"][peer]["verified"] = True
        self.store.save()

    def contacts(self) -> dict:
        return self.store.data["contacts"]

    # ---------- enviar ----------
    def send(self, peer: str, text: str) -> int:
        mine = self.keys.bundle()
        sess_d = self.store.data["sessions"].get(peer)
        if sess_d is None:
            bundle = self._fetch_verified_bundle(peer)
            init = x3dh.initiate(self.keys, bundle)
            session = Session.create(init.shared_key, mine.ik_sig_pub, bundle.ik_sig_pub, True, init.ek_pub)
        else:
            session = Session.from_dict(sess_d)
        n, ct = session.encrypt(text.encode("utf-8"))
        header = None
        if session.is_initiator and not session.confirmed:  # TODO Parte 3: reintento si se pierde el primero
            header = {"ik_sig_pub": b64e(mine.ik_sig_pub), "ik_dh_pub": b64e(mine.ik_dh_pub),
                      "ek_pub": b64e(session.ek_pub)}
        self.api.send(peer, header, n, b64e(ct))
        self.store.data["sessions"][peer] = session.to_dict()
        self.store.add_history(peer, "out", n, text)
        self.store.save()
        return n

    # ---------- recibir ----------
    def receive(self) -> list[Received]:
        results = []
        for m in self.api.fetch():
            sender = m["from"]
            try:
                session = self._session_for_incoming(sender, m["init"])
                text = session.decrypt(m["n"], b64d(m["ciphertext"])).decode("utf-8")
            except (InvalidTag, ReplayError, TooManySkippedError, BundleSignatureError,
                    IdentityChangedError, ValueError, KeyError) as exc:
                results.append(Received(sender, m["n"], None, f"{type(exc).__name__}: {exc}"))
                continue
            self.store.data["sessions"][sender] = session.to_dict()
            self.store.add_history(sender, "in", m["n"], text)
            results.append(Received(sender, m["n"], text))
        self.store.save()
        return results

    def _session_for_incoming(self, sender: str, init: dict | None) -> Session:
        existing = self.store.data["sessions"].get(sender)
        if init is None:
            if existing is None:
                raise KeyError("mensaje sin sesión ni cabecera X3DH")
            return Session.from_dict(existing)
        # Mensaje inicial: se autentica la identidad de A pidiendo SU bundle al servidor y comparándolo.
        if existing and b64d(init["ek_pub"]) == Session.from_dict(existing).ek_pub:
            return Session.from_dict(existing)  # reenvío de la cabecera de una sesión ya creada
        bundle = self._fetch_verified_bundle(sender)
        if b64e(bundle.ik_sig_pub) != init["ik_sig_pub"] or b64e(bundle.ik_dh_pub) != init["ik_dh_pub"]:
            raise IdentityChangedError("la cabecera X3DH no coincide con el bundle publicado")
        sk = x3dh.respond(self.keys, bundle.ik_dh_pub, b64d(init["ek_pub"]))
        mine = self.keys.bundle()
        # TODO Parte 3: ambos inician a la vez (dos sesiones simultáneas); aquí gana la más reciente.
        return Session.create(sk, mine.ik_sig_pub, bundle.ik_sig_pub, False, b64d(init["ek_pub"]))
