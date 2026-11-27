# Plan de trabajo (4 integrantes)

## Reparto

| Parte | Integrante | Qué es | Estado |
|---|---|---|---|
| 1. Núcleo criptográfico | Luis Angel Castillo Mahecha | `securechat/crypto/` | Base hecha y probada |
| 2. Servidor | Ivan David Monroy Molano | `securechat/server/` | Base hecha y probada |
| 3. Cliente | Julian Cardona Rojas | `securechat/client/` | Base hecha y probada |
| 4. Seguridad e integración | Santiago | `attacks/`, `scripts/`, Docker, docs, informe, video | Base hecha, falta mucho |

(Cada parte tiene su lista de pendientes en `docs/PARTE_1_crypto.md` … `docs/PARTE_4_integracion.md`.)

## Cómo subir esto a Git (una sola persona, una sola vez)

```bash
unzip securechat.zip && cd securechat
git init -b main
git config user.name "Su Nombre" && git config user.email "su@correo"
python scripts/check_no_secrets.py          # debe decir: Sin secretos detectados.
git add . && git commit -m "Esqueleto inicial del proyecto (4 partes)"
git remote add origin <URL> && git push -u origin main
```

Después, **cada integrante** clona el repo, configura SU nombre y correo en git, crea una rama por tarea
(`git checkout -b parte1/borrado-claves`), hace commits pequeños y abre un pull request. El profesor revisa que
haya aportes de todos en el historial: no haga commits a nombre de otra persona.

## Orden sugerido

1. **Antes del hito E2 (viernes 20 nov):** que todos corran `pytest` y `attacks/run_all.py` y entiendan el flujo
   (X3DH → ratchet → AES-GCM). Cada quien completa los pendientes "Prioridad alta" de su parte.
2. **Semana 3 (23-27 nov):** pendientes "Prioridad media", ataque 6, informe E4 (máx. 15 págs.), guion y video E6.
3. **Cierre (30 nov):** probar desde un clon limpio (`git clone` + `docker compose up`), correr `check_no_secrets.py`,
   entregar en Moodle. Sustentación el 1 de diciembre.

## Lista de verificación final (rúbrica)

- [ ] C1 AEAD: nonces únicos por diseño, AD con identidades y contador (explicado en el informe)
- [ ] C2 Claves públicas siempre autenticadas (firma del bundle + TOFU + safety number)
- [ ] C3 Argon2id en servidor y almacén local; tokens aleatorios con expiración
- [ ] C4 Verificación de firma obligatoria (probada en `attack_01`)
- [ ] C5 Tabla de usos del hash con parámetros justificados (medir Argon2id y justificar m, t, p)
- [ ] C6 Modelo de amenazas STRIDE ligado a cada decisión de diseño
- [ ] C7 Tres o más ataques reproducibles con evidencia (hay 5; falta capturar evidencia en sus máquinas)
- [ ] C8 README reproducible, sin secretos en el historial, aportes de los 4 en Git
- [ ] C9 Informe claro; los 4 responden preguntas individuales sobre TODO el sistema
