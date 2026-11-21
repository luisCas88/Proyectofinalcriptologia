"""Ratchet simétrico (cadena HMAC-SHA256) y sesión cifrada.

  CK_0 = HKDF(SK, "chain/<dirección>")           una cadena por dirección
  MK_i = HMAC-SHA256(CK_i, 0x01)                 clave del mensaje i
  CK_{i+1} = HMAC-SHA256(CK_i, 0x02)             siguiente eslabón (CK_i se descarta)

Datos asociados (AD): etiqueta || IK_sig_pub_emisor || IK_sig_pub_receptor || N (8 bytes).
Esto ata cada mensaje a ambas identidades y a su posición en la cadena (frena replay y reordenamiento).

LIMITACIÓN CONOCIDA (documentar en el informe): Python no garantiza borrar bytes de memoria;
aquí se descartan las referencias. Mejora opcional: usar bytearray y sobrescribir con ceros.
"""
import hmac
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from .aead import decrypt_message, encrypt_message
from .encoding import b64d, b64e
from .kdf import hkdf

MAX_SKIP = 100  # máximo de claves de mensajes omitidos que se guardan (mensajes fuera de orden)


class ReplayError(Exception):
    """Mensaje repetido o ya consumido."""


class TooManySkippedError(Exception):
    pass


def chain_step(ck: bytes) -> tuple[bytes, bytes]:
    mk = hmac.new(ck, b"\x01", "sha256").digest()
    next_ck = hmac.new(ck, b"\x02", "sha256").digest()
    return mk, next_ck


def build_ad(sender_ik_sig_pub: bytes, receiver_ik_sig_pub: bytes, n: int) -> bytes:
    return b"securechat/v1/ad" + sender_ik_sig_pub + receiver_ik_sig_pub + n.to_bytes(8, "big")


@dataclass
class Session:
    own_ik_sig_pub: bytes
    peer_ik_sig_pub: bytes
    send_ck: bytes
    recv_ck: bytes
    send_n: int = 0
    recv_n: int = 0
    skipped: dict = field(default_factory=dict)  # n -> MK (mensajes omitidos aún no recibidos)
    ek_pub: bytes = b""  # EK de A que originó la sesión (para reconocer re-envíos del primer mensaje)
    is_initiator: bool = False
    confirmed: bool = False  # el iniciador deja de enviar la cabecera X3DH tras recibir respuesta

    @classmethod
    def create(cls, shared_key: bytes, own_ik_sig_pub: bytes, peer_ik_sig_pub: bytes,
               initiator: bool, ek_pub: bytes) -> "Session":
        a2b = hkdf(shared_key, b"securechat/v1/chain/A->B")
        b2a = hkdf(shared_key, b"securechat/v1/chain/B->A")
        send_ck, recv_ck = (a2b, b2a) if initiator else (b2a, a2b)
        return cls(own_ik_sig_pub, peer_ik_sig_pub, send_ck, recv_ck, ek_pub=ek_pub,
                   is_initiator=initiator, confirmed=not initiator)

    # ---- enviar ----
    def encrypt(self, plaintext: bytes) -> tuple[int, bytes]:
        mk, self.send_ck = chain_step(self.send_ck)
        n = self.send_n
        self.send_n += 1
        ad = build_ad(self.own_ik_sig_pub, self.peer_ik_sig_pub, n)
        ct = encrypt_message(mk, plaintext, ad)
        del mk  # MK usada una sola vez
        return n, ct

    # ---- recibir ----
    def decrypt(self, n: int, ciphertext: bytes) -> bytes:
        """Lanza ReplayError / InvalidTag. El estado solo avanza si el mensaje autentica."""
        ad = build_ad(self.peer_ik_sig_pub, self.own_ik_sig_pub, n)

        if n in self.skipped:  # mensaje fuera de orden que llega tarde
            pt = decrypt_message(self.skipped[n], ciphertext, ad)
            del self.skipped[n]
            return pt
        if n < self.recv_n:
            raise ReplayError(f"mensaje {n} ya recibido (replay)")
        if n - self.recv_n > MAX_SKIP:
            raise TooManySkippedError(f"salto demasiado grande ({n - self.recv_n})")

        # Se calcula sobre copias y solo se confirma si la etiqueta GCM es válida.
        ck, new_skipped = self.recv_ck, {}
        for i in range(self.recv_n, n):
            mk_i, ck = chain_step(ck)
            new_skipped[i] = mk_i
        mk_n, next_ck = chain_step(ck)
        pt = decrypt_message(mk_n, ciphertext, ad)  # InvalidTag => no se modifica el estado
        self.skipped.update(new_skipped)
        self.recv_ck, self.recv_n = next_ck, n + 1
        self.confirmed = True
        return pt

    # ---- persistencia (se guarda cifrada en el almacén local del cliente) ----
    def to_dict(self) -> dict:
        return {
            "own": b64e(self.own_ik_sig_pub), "peer": b64e(self.peer_ik_sig_pub),
            "send_ck": b64e(self.send_ck), "recv_ck": b64e(self.recv_ck),
            "send_n": self.send_n, "recv_n": self.recv_n,
            "skipped": {str(k): b64e(v) for k, v in self.skipped.items()},
            "ek_pub": b64e(self.ek_pub), "is_initiator": self.is_initiator, "confirmed": self.confirmed,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        return cls(b64d(d["own"]), b64d(d["peer"]), b64d(d["send_ck"]), b64d(d["recv_ck"]),
                   d["send_n"], d["recv_n"], {int(k): b64d(v) for k, v in d["skipped"].items()},
                   b64d(d["ek_pub"]), d["is_initiator"], d["confirmed"])


__all__ = ["Session", "ReplayError", "TooManySkippedError", "InvalidTag", "chain_step", "build_ad"]
