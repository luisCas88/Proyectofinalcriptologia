# Parte 1: Núcleo criptográfico (`securechat/crypto/`)
Responsable: Luis Angel Castillo Mahecha (arquitectura criptográfica)

## Ya hecho (y probado con `pytest tests/test_crypto_core.py`)
- `kdf.py`: HKDF-SHA256 y Argon2id (m=64 MiB, t=3, p=4), hash y verificación de contraseñas en tiempo constante.
- `aead.py`: AES-256-GCM con clave y nonce derivados de cada clave de mensaje (nonce único por diseño); sellado del almacén local.
- `keys.py`: claves de identidad (Ed25519 + X25519), signed prekey, bundle y verificación de firma.
- `x3dh.py`: X3DH simplificado (3 DH + HKDF); `initiate` verifica la firma antes de calcular nada.
- `ratchet.py`: ratchet simétrico HMAC-SHA256, AD con identidades y contador, replay, mensajes fuera de orden, serialización.
- `safety.py`: safety number de 60 dígitos y huella.

## Pendientes
**Prioridad alta**
- [ ] Revisar TODO el código y poder explicar cada línea (sustentación individual).
- [ ] Medir el tiempo de Argon2id en una máquina del grupo y justificar m, t, p en el informe (criterio C5).
- [ ] Borrado de claves efímeras: usar `bytearray` y sobrescribir con ceros (ahora solo se descartan referencias).
- [ ] Más pruebas: vectores conocidos de HKDF (RFC 5869) y de Ed25519/X25519 (RFC 8032 / 7748).

**Prioridad media**
- [ ] Documentar en el informe por qué las AD incluyen `IK_sig_pub` de ambos y el contador `N`.
- [ ] Decidir y justificar la política de rotación de la signed prekey.

**Bonificación (opcional, hasta 5 %)**
- [ ] Double Ratchet completo (ratchet Diffie-Hellman).
- [ ] Acuerdo híbrido X25519 + ML-KEM-768 estilo PQXDH (requiere autorización del docente para liboqs).
- [ ] One-time prekeys.
