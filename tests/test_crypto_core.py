"""Pruebas de la PARTE 1 (núcleo criptográfico). Ejecutar: pytest tests/test_crypto_core.py -q"""
import pytest
from cryptography.exceptions import InvalidTag

from securechat.crypto import aead, kdf, x3dh
from securechat.crypto.keys import BundleSignatureError, IdentityKeys, verify_bundle
from securechat.crypto.ratchet import ReplayError, Session
from securechat.crypto.safety import safety_number


def make_pair():
    a, b = IdentityKeys.generate(), IdentityKeys.generate()
    init = x3dh.initiate(a, b.bundle())
    sk_b = x3dh.respond(b, a.bundle().ik_dh_pub, init.ek_pub)
    assert init.shared_key == sk_b
    sa = Session.create(init.shared_key, a.bundle().ik_sig_pub, b.bundle().ik_sig_pub, True, init.ek_pub)
    sb = Session.create(sk_b, b.bundle().ik_sig_pub, a.bundle().ik_sig_pub, False, init.ek_pub)
    return a, b, sa, sb


def test_aead_roundtrip_and_tamper():
    mk = b"k" * 32
    ct = aead.encrypt_message(mk, b"hola", b"ad")
    assert aead.decrypt_message(mk, ct, b"ad") == b"hola"
    bad = bytearray(ct); bad[0] ^= 1
    with pytest.raises(InvalidTag):
        aead.decrypt_message(mk, bytes(bad), b"ad")
    with pytest.raises(InvalidTag):  # AD distintos también se rechazan
        aead.decrypt_message(mk, ct, b"otro")


def test_bundle_signature_must_verify():
    a = IdentityKeys.generate()
    bundle = a.bundle()
    verify_bundle(bundle)
    bundle.spk_pub = IdentityKeys.generate().bundle().spk_pub  # sustitución de la signed prekey
    with pytest.raises(BundleSignatureError):
        verify_bundle(bundle)


def test_x3dh_refuses_forged_bundle():
    a, b = IdentityKeys.generate(), IdentityKeys.generate()
    forged = b.bundle()
    forged.spk_pub = IdentityKeys.generate().bundle().spk_pub
    with pytest.raises(BundleSignatureError):
        x3dh.initiate(a, forged)


def test_session_messages_in_order_and_out_of_order():
    _, _, sa, sb = make_pair()
    msgs = [sa.encrypt(f"m{i}".encode()) for i in range(4)]
    assert sb.decrypt(*msgs[0]) == b"m0"
    assert sb.decrypt(*msgs[3]) == b"m3"  # salta 1 y 2
    assert sb.decrypt(*msgs[1]) == b"m1"  # llegan tarde
    assert sb.decrypt(*msgs[2]) == b"m2"


def test_replay_is_rejected():
    _, _, sa, sb = make_pair()
    n, ct = sa.encrypt(b"x")
    sb.decrypt(n, ct)
    with pytest.raises(ReplayError):
        sb.decrypt(n, ct)


def test_tamper_does_not_advance_state():
    _, _, sa, sb = make_pair()
    n, ct = sa.encrypt(b"x")
    bad = bytearray(ct); bad[-1] ^= 1
    with pytest.raises(InvalidTag):
        sb.decrypt(n, bytes(bad))
    assert sb.recv_n == 0 and sb.decrypt(n, ct) == b"x"  # el original aún se acepta


def test_forward_secrecy_old_keys_not_recoverable():
    _, _, sa, sb = make_pair()
    old = [sa.encrypt(f"old{i}".encode()) for i in range(3)]
    for n, ct in old:
        sb.decrypt(n, ct)
    # Se filtra TODO el estado actual del receptor: no debe poder descifrar mensajes viejos.
    leaked = Session.from_dict(sb.to_dict())
    for n, ct in old:
        with pytest.raises(ReplayError):
            leaked.decrypt(n, ct)


def test_session_serialization_roundtrip():
    _, _, sa, sb = make_pair()
    sb2 = Session.from_dict(sb.to_dict())
    n, ct = sa.encrypt(b"persistido")
    assert sb2.decrypt(n, ct) == b"persistido"


def test_safety_number_is_symmetric_and_detects_change():
    a, b, c = IdentityKeys.generate().bundle(), IdentityKeys.generate().bundle(), IdentityKeys.generate().bundle()
    n1 = safety_number(a.ik_sig_pub, a.ik_dh_pub, b.ik_sig_pub, b.ik_dh_pub)
    n2 = safety_number(b.ik_sig_pub, b.ik_dh_pub, a.ik_sig_pub, a.ik_dh_pub)
    n3 = safety_number(a.ik_sig_pub, a.ik_dh_pub, c.ik_sig_pub, c.ik_dh_pub)
    assert n1 == n2 and n1 != n3 and len(n1.replace(" ", "")) == 60


def test_password_hash_and_local_store():
    salt, h = kdf.hash_password("clave-larga-123")
    assert kdf.verify_password("clave-larga-123", salt, h)
    assert not kdf.verify_password("otra", salt, h)
    blob = aead.seal_json("frase", {"a": 1})
    assert aead.open_json("frase", blob) == {"a": 1}
    with pytest.raises(InvalidTag):
        aead.open_json("incorrecta", blob)
