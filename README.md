# SecureChat: mensajería segura extremo a extremo

Proyecto Final de Criptografía Aplicada (Ingeniería en Telemática, Universidad Distrital).
Alternativa A: versión simplificada del protocolo Signal (X3DH simplificado + ratchet simétrico + AES-256-GCM).

> **Estado: VERSIÓN INICIAL** El flujo básico ya funciona de extremo a extremo
> y 5 de los ataques ya se demuestran fallidos. Lo que falta está listado en `docs/PARTE_*.md`.

## Ejecutar (sin Docker)

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest tests -q            # 12 pruebas: criptografía + flujo extremo a extremo
python scripts/demo_e2.py            # demostración E2: registro, login, cifrado, descifrado
python attacks/run_all.py            # demuestra los ataques fallidos y guarda evidencia

# Uso manual (3 terminales; cambie las contraseñas por las suyas):
python -m securechat.server                               # terminal 1: servidor en :8000
python -m securechat.client --user alice register         # terminal 2
python -m securechat.client --user bob register           # terminal 3
python -m securechat.client --user alice send bob "hola"
python -m securechat.client --user bob inbox
python -m securechat.client --user bob safety alice       # compare este número con el de Alice
python -m securechat.client --user bob                    # sin comando: abre el menú interactivo
```

## Ejecutar con Docker

Requiere Docker Desktop (o Docker Engine + Compose v2). Una sola imagen sirve para todo.

```bash
docker compose build
docker compose up -d server                 # servidor en http://localhost:8000 (BD en el volumen server-data)
docker compose ps                           # debe aparecer "healthy"

# Cliente interactivo (pide frase local y contraseña; las claves quedan en el volumen client-home)
docker compose run --rm client --user alice register
docker compose run --rm client --user bob register
docker compose run --rm client --user alice send bob "hola"
docker compose run --rm client --user bob inbox
docker compose run --rm client --user bob safety alice

docker compose --profile tests run --rm tests       # pruebas
docker compose --profile attacks run --rm attacks   # ataques; evidencia en attacks/evidence/

docker compose down -v                      # parar y borrar volúmenes (BD y claves de los clientes)
```

## Estructura = las 4 partes del equipo

| Parte | Carpeta | Responsable (rol) |
|---|---|---|
| 1 | `securechat/crypto/` + `tests/test_crypto_core.py` | Arquitectura criptográfica |
| 2 | `securechat/server/` | Desarrollo del servidor |
| 3 | `securechat/client/` | Desarrollo del cliente |
| 4 | `attacks/`, `scripts/`, `docs/`, Docker, `tests/test_e2e.py`, informe y video | Análisis de seguridad e integración |

Guía de trabajo, pendientes por parte y plan de commits: `docs/PLAN_DE_TRABAJO.md`.
