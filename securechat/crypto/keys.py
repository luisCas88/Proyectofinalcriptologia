"""Claves de identidad, signed prekey y prekey bundle.

Cada usuario genera EN SU CLIENTE:
  IK_sig  Ed25519  (identidad, firma)
  IK_dh   X25519   (identidad, acuerdo de claves)
  SPK     X25519   (signed prekey)
  Sig_SPK = Ed25519.Sign(IK_sig, IK_dh_pub || SPK_pub)
Al servidor solo se envían las claves públicas y la firma (el bundle).
"""
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .encoding import b64d, b64e

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
_RAW_PRIV = dict(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)


class BundleSignatureError(Exception):
    """La firma de la signed prekey NO es válida: posible MITM del servidor."""


def pub_bytes(key) -> bytes:
    return key.public_key().public_bytes(**_RAW)


@dataclass
class PreKeyBundle:
    ik_sig_pub: bytes
    ik_dh_pub: bytes
    spk_pub: bytes
    sig_spk: bytes

    def to_dict(self) -> dict:
        return {k: b64e(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d: dict) -> "PreKeyBundle":
        return cls(**{k: b64d(d[k]) for k in ("ik_sig_pub", "ik_dh_pub", "spk_pub", "sig_spk")})


def verify_bundle(bundle: PreKeyBundle) -> None:
    """Verificación OBLIGATORIA antes de usar cualquier clave pública ajena (criterio C4)."""
    try:
        Ed25519PublicKey.from_public_bytes(bundle.ik_sig_pub).verify(
            bundle.sig_spk, bundle.ik_dh_pub + bundle.spk_pub
        )
    except (InvalidSignature, ValueError) as exc:
        raise BundleSignatureError("firma de la signed prekey inválida") from exc


@dataclass
class IdentityKeys:
    ik_sig: Ed25519PrivateKey
    ik_dh: X25519PrivateKey
    spk: X25519PrivateKey

    @classmethod
    def generate(cls) -> "IdentityKeys":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate(), X25519PrivateKey.generate())

    def bundle(self) -> PreKeyBundle:
        ik_dh_pub, spk_pub = pub_bytes(self.ik_dh), pub_bytes(self.spk)
        return PreKeyBundle(
            ik_sig_pub=pub_bytes(self.ik_sig),
            ik_dh_pub=ik_dh_pub,
            spk_pub=spk_pub,
            sig_spk=self.ik_sig.sign(ik_dh_pub + spk_pub),
        )

    def to_dict(self) -> dict:
        return {
            "ik_sig": b64e(self.ik_sig.private_bytes(**_RAW_PRIV)),
            "ik_dh": b64e(self.ik_dh.private_bytes(**_RAW_PRIV)),
            "spk": b64e(self.spk.private_bytes(**_RAW_PRIV)),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IdentityKeys":
        return cls(
            Ed25519PrivateKey.from_private_bytes(b64d(d["ik_sig"])),
            X25519PrivateKey.from_private_bytes(b64d(d["ik_dh"])),
            X25519PrivateKey.from_private_bytes(b64d(d["spk"])),
        )


def x25519_public(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)
