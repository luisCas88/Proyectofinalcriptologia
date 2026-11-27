"""ATAQUE 5: se vuelca la base de datos del servidor.
Mecanismo que lo detiene: solo hay claves públicas, hashes Argon2id, tokens hasheados y textos cifrados."""
from _lab import Lab, verdict

SECRET_TEXT = "SECRETO-ALTAMENTE-CONFIDENCIAL-12345"


def main() -> int:
    print("ATAQUE 5: volcado de la base de datos del servidor")
    with Lab() as lab:
        alice, _bob = lab.client("alice"), lab.client("bob")
        alice.send("bob", SECRET_TEXT)
        raw = open(lab.db, "rb").read()
        tables = [r[0] for r in lab.db_execute("SELECT name FROM sqlite_master WHERE type='table'")]
        print(f"  Tablas volcadas: {tables}")
        for who in ("alice", "bob"):
            pw, _ = lab.secrets[who]
            if pw.encode() in raw:
                return verdict(False, "", f"la contraseña de {who} aparece en claro en la base de datos")
        row = lab.db_execute("SELECT ciphertext FROM messages")[0][0]
        print(f"  Mensaje almacenado (cifrado): {row[:48]}...")
        if SECRET_TEXT.encode() in raw:
            return verdict(False, "", "el texto plano aparece en la base de datos")
        return verdict(True, "no hay texto plano ni contraseñas; solo cifrados, hashes y claves públicas.", "")


if __name__ == "__main__":
    raise SystemExit(main())
