"""ATAQUE 1: el servidor sustituye la signed prekey de B por una propia (MITM).
Mecanismo que lo detiene: verificación de la firma Ed25519 con la identidad de B."""
from _lab import Lab, verdict
from securechat.crypto.encoding import b64e
from securechat.crypto.keys import BundleSignatureError, IdentityKeys


def main() -> int:
    print("ATAQUE 1: sustitución de la signed prekey")
    with Lab() as lab:
        alice, _bob = lab.client("alice"), lab.client("bob")
        evil = IdentityKeys.generate().bundle()
        lab.db_execute("UPDATE users SET spk_pub=? WHERE username='bob'", (b64e(evil.spk_pub),))
        print("  El atacante reemplazó SPK_B en la base de datos del servidor.")
        try:
            alice.send("bob", "mensaje secreto")
        except BundleSignatureError as e:
            return verdict(True, f"Alice rechazó el bundle ({e}); no se envió nada.", "")
        return verdict(False, "", "Alice aceptó una SPK falsa.")


if __name__ == "__main__":
    raise SystemExit(main())
