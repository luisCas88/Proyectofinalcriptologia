"""X3DH simplificado [Marlinspike y Perrin, 2016]: identidad + signed prekey + clave efímera.

DH1 = DH(IK_dh_A, SPK_B)    DH2 = DH(EK_A, IK_dh_B)    DH3 = DH(EK_A, SPK_B)
SK  = HKDF-SHA256(F || DH1 || DH2 || DH3),  F = 32 bytes 0xFF
(sin one-time prekeys: son opcionales en el alcance mínimo)
"""
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .kdf import hkdf
from .keys import IdentityKeys, PreKeyBundle, pub_bytes, verify_bundle, x25519_public

F = b"\xff" * 32
SALT = b"\x00" * 32
X3DH_INFO = b"securechat/v1/x3dh"


@dataclass
class InitResult:
    shared_key: bytes  # SK
    ek_pub: bytes  # clave efímera pública que se envía con el primer mensaje


def _sk(dh1: bytes, dh2: bytes, dh3: bytes) -> bytes:
    return hkdf(F + dh1 + dh2 + dh3, info=X3DH_INFO, length=32, salt=SALT)


def initiate(own: IdentityKeys, peer_bundle: PreKeyBundle) -> InitResult:
    """Lado A. Verifica la firma del bundle de B ANTES de calcular nada."""
    verify_bundle(peer_bundle)  # lanza BundleSignatureError si fue sustituido
    ek = X25519PrivateKey.generate()
    ik_b = x25519_public(peer_bundle.ik_dh_pub)
    spk_b = x25519_public(peer_bundle.spk_pub)
    sk = _sk(own.ik_dh.exchange(spk_b), ek.exchange(ik_b), ek.exchange(spk_b))
    ek_pub = pub_bytes(ek)
    del ek  # la efímera privada no se guarda (TODO Parte 1: borrado explícito de DH intermedios)
    return InitResult(sk, ek_pub)


def respond(own: IdentityKeys, peer_ik_dh_pub: bytes, ek_pub: bytes) -> bytes:
    """Lado B. `peer_ik_dh_pub` debe venir de un bundle ya verificado y autenticado."""
    ik_a = x25519_public(peer_ik_dh_pub)
    ek_a = x25519_public(ek_pub)
    return _sk(own.spk.exchange(ik_a), own.ik_dh.exchange(ek_a), own.spk.exchange(ek_a))
