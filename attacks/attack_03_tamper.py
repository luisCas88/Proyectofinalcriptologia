"""ATAQUE 3: un atacante modifica un byte del texto cifrado en tránsito / en el servidor.
Mecanismo que lo detiene: falla la etiqueta de autenticación de AES-GCM."""
from _lab import Lab, verdict
from securechat.crypto.encoding import b64d, b64e


def main() -> int:
    print("ATAQUE 3: modificación de un byte del texto cifrado")
    with Lab() as lab:
        alice, bob = lab.client("alice"), lab.client("bob")
        alice.send("bob", "transferir 100")
        (row_id, ct), = lab.db_execute("SELECT id, ciphertext FROM messages")
        raw = bytearray(b64d(ct)); raw[0] ^= 0x01
        lab.db_execute("UPDATE messages SET ciphertext=? WHERE id=?", (b64e(bytes(raw)), row_id))
        print("  El atacante cambió 1 bit del mensaje almacenado.")
        r, = bob.receive()
        if r.text is None and "InvalidTag" in (r.error or ""):
            return verdict(True, f"Bob rechazó el mensaje ({r.error}).", "")
        return verdict(False, "", f"Bob aceptó un mensaje alterado: {r.text!r}")


if __name__ == "__main__":
    raise SystemExit(main())
