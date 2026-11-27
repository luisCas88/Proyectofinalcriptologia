"""Prueba extremo a extremo: registro, login, X3DH, mensajes en ambos sentidos, entrega offline."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "attacks"))
from _lab import Lab  # noqa: E402


def test_full_conversation_with_offline_delivery():
    with Lab() as lab:
        alice, bob = lab.client("alice"), lab.client("bob")
        alice.send("bob", "hola bob")  # Bob está "desconectado": el servidor solo guarda cifrado
        alice.send("bob", "¿estás?")
        got = bob.receive()
        assert [r.text for r in got] == ["hola bob", "¿estás?"]
        bob.send("alice", "aquí estoy")
        assert [r.text for r in alice.receive()] == ["aquí estoy"]
        alice.send("bob", "perfecto")  # ya sin cabecera X3DH
        assert [r.text for r in bob.receive()] == ["perfecto"]
        assert alice.safety_number("bob") == bob.safety_number("alice")
        assert alice.contacts()["bob"]["verified"] is False
        alice.mark_verified("bob")
        assert alice.contacts()["bob"]["verified"] is True
        assert len(alice.store.data["history"]) == 4


def test_wrong_password_and_unknown_user_rejected():
    import pytest
    from securechat.client.api import ApiError
    with Lab() as lab:
        lab.client("alice")
        c = lab.client("alice", register=False)
        c.api.token = None
        with pytest.raises(ApiError):
            c.api.login("alice", "contraseña-incorrecta")
        with pytest.raises(ApiError):
            c.api.login("nadie", "contraseña-incorrecta")
