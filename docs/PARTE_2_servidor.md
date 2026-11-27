# Parte 2: Servidor (`securechat/server/`)
Responsable: Ivan David Monroy Molano (desarrollo del servidor)

## Ya hecho
- FastAPI + SQLite: `POST /register`, `POST /login`, `GET /bundle/{usuario}`, `POST /messages`, `GET /messages`, `GET /health`.
- Contraseñas con Argon2id y sal; el servidor valida la firma del bundle al registrar.
- Tokens de 256 bits aleatorios, expiran en 1 hora, se guardan como SHA-256.
- Límite básico de intentos de login (5 en 5 minutos, en memoria) y trabajo ficticio si el usuario no existe.
- Cada usuario solo lee su propio buzón. El servidor solo guarda cifrados y claves públicas.

## Pendientes
**Prioridad alta**
- [ ] Confirmación de entrega: hoy `GET /messages` borra los mensajes al leerlos; si el cliente falla se pierden. Cambiar a `GET` + `POST /messages/ack`.
- [ ] Reemplazar `@app.on_event("startup")` por `lifespan` (está obsoleto en FastAPI).
- [ ] Pruebas de la API (códigos de error, usuario duplicado, token expirado, buzón ajeno).

**Prioridad media**
- [ ] Endpoint para rotar la signed prekey (con firma verificada).
- [ ] Límite de tamaño de mensaje y de cantidad de mensajes pendientes.
- [ ] Persistir el límite de intentos de login y limitar también por IP.
- [ ] Endpoint de cierre de sesión (`/logout`) que borre el token.
- [ ] Revisar que ningún log imprima contraseñas, tokens ni textos cifrados.
- [ ] HTTPS/WSS opcional (el sistema NO depende de TLS, pero conviene mostrarlo). Entrega por WebSocket como opción.

**Bonificación**
- [ ] Chats de grupo con sender keys (requiere cambios coordinados con Partes 1 y 3).
