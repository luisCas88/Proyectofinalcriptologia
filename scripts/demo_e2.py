"""DEMOSTRACIÓN E2 (hito 20 de noviembre): flujo extremo a extremo básico.

registro -> autenticación -> X3DH -> cifrado -> entrega offline -> descifrado -> respuesta
-> safety number -> rechazo de un mensaje alterado.
Uso:  python scripts/demo_e2.py        (levanta un servidor temporal; no deja datos ni secretos)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "attacks"))
from _lab import Lab  # noqa: E402

from securechat.crypto.encoding import b64d, b64e  # noqa: E402


def paso(n, titulo):
    print(f"\n=== PASO {n}: {titulo} ===")


def main() -> int:
    with Lab() as lab:
        paso(1, "Registro. Las claves se generan en el CLIENTE; al servidor solo viaja la parte pública")
        alice, bob = lab.client("alice"), lab.client("bob")
        fila = lab.db_execute("SELECT username, length(pw_hash), substr(ik_sig_pub,1,16), substr(sig_spk,1,16) FROM users")
        for u, lh, ik, sg in fila:
            print(f"  servidor guarda -> usuario={u} | hash Argon2id de {lh} bytes (no la contraseña) | IK_sig_pub={ik}... | firma SPK={sg}...")
        print("  claves privadas: solo en el almacén local cifrado de cada cliente (Argon2id + AES-256-GCM)")

        paso(2, "Autenticación. Argon2id en el servidor y token de sesión aleatorio de 256 bits")
        print(f"  token de Alice (longitud) = {len(alice.api.token)} caracteres; el servidor guarda solo su SHA-256")

        paso(3, "Alice escribe a Bob mientras Bob está desconectado (X3DH + AES-256-GCM)")
        alice.send("bob", "Hola Bob, este mensaje viaja cifrado de extremo a extremo")
        ct = lab.db_execute("SELECT n, ciphertext FROM messages")[0]
        print(f"  lo único que el servidor tiene del mensaje #{ct[0]} -> {ct[1][:60]}...")
        print("  el texto en claro NO está en el servidor")

        paso(4, "Bob se conecta, verifica la firma del bundle de Alice, deriva la misma clave y descifra")
        for r in bob.receive():
            print(f"  Bob recibió de {r.sender} #{r.n}: {r.text!r}" if r.text else f"  RECHAZADO: {r.error}")

        paso(5, "Bob responde y Alice descifra (ratchet: clave nueva por mensaje)")
        bob.send("alice", "Recibido, Alice")
        for r in alice.receive():
            print(f"  Alice recibió de {r.sender} #{r.n}: {r.text!r}")

        paso(6, "Verificación de identidad: safety number idéntico en ambos lados")
        sa, sb = alice.safety_number("bob"), bob.safety_number("alice")
        print(f"  Alice ve: {sa}\n  Bob ve  : {sb}\n  coinciden: {sa == sb}")
        alice.mark_verified("bob")
        print(f"  Alice marca a Bob como verificado: {alice.contacts()['bob']['verified']}")

        paso(7, "Un byte alterado en el servidor se rechaza (falla la etiqueta de AES-GCM)")
        alice.send("bob", "mensaje que será alterado")
        i, c = lab.db_execute("SELECT id, ciphertext FROM messages")[0]
        raw = bytearray(b64d(c)); raw[0] ^= 1
        lab.db_execute("UPDATE messages SET ciphertext=? WHERE id=?", (b64e(bytes(raw)), i))
        r, = bob.receive()
        print(f"  resultado en Bob: {'ACEPTADO (FALLO)' if r.text else 'rechazado -> ' + r.error.split(':')[0]}")
        return 0 if (sa == sb and r.text is None) else 1


if __name__ == "__main__":
    code = main()
    print("\nRESULTADO DE LA DEMOSTRACIÓN:", "FLUJO E2E CORRECTO" if code == 0 else "HAY FALLOS")
    raise SystemExit(code)
