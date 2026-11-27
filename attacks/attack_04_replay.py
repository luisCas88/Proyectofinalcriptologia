"""ATAQUE 4: un atacante reenvía un mensaje antiguo (replay).
Mecanismo que lo detiene: contador N en los datos asociados + registro de mensajes ya recibidos."""
from _lab import Lab, verdict


def main() -> int:
    print("ATAQUE 4: replay de un mensaje antiguo")
    with Lab() as lab:
        alice, bob = lab.client("alice"), lab.client("bob")
        alice.send("bob", "pago aprobado")
        saved = lab.db_execute("SELECT sender, recipient, init, n, ciphertext, ts FROM messages")[0]
        first, = bob.receive()
        print(f"  Primera entrega: {first.text!r}")
        lab.db_execute("INSERT INTO messages (sender, recipient, init, n, ciphertext, ts) VALUES (?,?,?,?,?,?)", saved)
        print("  El atacante volvió a inyectar el mismo mensaje en el buzón de Bob.")
        replayed, = bob.receive()
        if replayed.text is None and "ReplayError" in (replayed.error or ""):
            return verdict(True, f"Bob descartó el replay ({replayed.error}).", "")
        return verdict(False, "", "Bob aceptó el mensaje repetido.")


if __name__ == "__main__":
    raise SystemExit(main())
