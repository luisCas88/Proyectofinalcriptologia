"""Safety number: huella comparable por un canal externo (en persona, QR).

Hash SHA-256 sobre las dos identidades (IK_sig_pub || IK_dh_pub de cada usuario) ordenadas
lexicográficamente (ambos usuarios ven el mismo número). Se muestra como 60 dígitos en grupos de 5.
"""
import hashlib


def fingerprint(ik_sig_pub: bytes, ik_dh_pub: bytes) -> str:
    return hashlib.sha256(ik_sig_pub + ik_dh_pub).hexdigest()


def safety_number(a_sig: bytes, a_dh: bytes, b_sig: bytes, b_dh: bytes) -> str:
    first, second = sorted([a_sig + a_dh, b_sig + b_dh])
    digest = hashlib.sha256(b"securechat/v1/safety" + first + second).digest()
    digits = str(int.from_bytes(digest, "big") % 10**60).zfill(60)
    return " ".join(digits[i:i + 5] for i in range(0, 60, 5))
