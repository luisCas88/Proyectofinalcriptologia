"""ATAQUE 2: el servidor sustituye TAMBIÉN la clave de identidad de B (bundle propio y bien firmado).
Mecanismo que lo detiene: TOFU + safety number; se muestra alerta de cambio de identidad."""
from _lab import Lab, verdict
from securechat.client.core import IdentityChangedError
from securechat.crypto.keys import IdentityKeys
from securechat.crypto.safety import safety_number


def main() -> int:
    print("ATAQUE 2: sustitución de la clave de identidad")
    with Lab() as lab:
        alice, _bob = lab.client("alice"), lab.client("bob")
        alice.refresh_contact("bob")  # primer contacto: Alice fija la identidad real de Bob
        before = alice.safety_number("bob")
        evil = IdentityKeys.generate().bundle()  # bundle del atacante, con firma VÁLIDA
        lab.db_execute(
            "UPDATE users SET ik_sig_pub=?, ik_dh_pub=?, spk_pub=?, sig_spk=? WHERE username='bob'",
            tuple(v for v in evil.to_dict().values()))
        mine = alice.keys.bundle()
        after = safety_number(mine.ik_sig_pub, mine.ik_dh_pub, evil.ik_sig_pub, evil.ik_dh_pub)
        print(f"  Safety number antes : {before}\n  Safety number ahora : {after}")
        try:
            alice.refresh_contact("bob")
        except IdentityChangedError as e:
            return verdict(True, f"alerta mostrada al usuario -> {e}", "")
        return verdict(False, "", "Alice aceptó una identidad distinta sin alertar.")


if __name__ == "__main__":
    raise SystemExit(main())
