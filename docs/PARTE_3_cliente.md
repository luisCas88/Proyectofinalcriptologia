# Parte 3: Cliente de consola (`securechat/client/`)
Responsable: Julian Cardona Rojas (desarrollo del cliente)

## Ya hecho
- `core.py`: registro, login, contactos con TOFU, envío y recepción de mensajes, safety number, marcar verificado.
- Verificación obligatoria del bundle (firma) y alerta `IdentityChangedError` cuando cambia la identidad de un contacto.
- Un mensaje alterado o repetido se rechaza sin modificar el estado de la sesión.
- `store.py`: almacén local cifrado con Argon2id + AES-256-GCM (claves privadas, sesiones, contactos, historial).
- `cli.py`: `register`, `send`, `inbox`, `contacts`, `safety`, `verify`, `history`.

## Pendientes
**Prioridad alta**
- [ ] Alerta visible: hoy el cambio de identidad en `inbox` aparece como mensaje "RECHAZADO". Mostrar un aviso claro y bloquear el envío hasta que el usuario decida.
- [ ] Reintento del mensaje inicial: si se pierde el primer mensaje con cabecera X3DH, B no puede crear la sesión.
- [ ] Re-login automático si el token expira (1 hora).
- [ ] Probar la CLI a mano con 2 usuarios y poder explicar cada comando.

**Prioridad media**
- [ ] Ambos usuarios inician sesión a la vez: hoy gana la más reciente; resolver de forma determinista (p. ej. por orden de nombre de usuario).
- [ ] Modo interactivo (chat en tiempo real con sondeo) en lugar de comandos sueltos.
- [ ] Mostrar el indicador verificado / no verificado en el directorio de contactos y en cada mensaje.
- [ ] Código QR del safety number (consultar al docente si `qrcode` está permitida).
- [ ] Rotación de la signed prekey desde el cliente.

**Bonificación**
- [ ] Envío de archivos adjuntos cifrados.
