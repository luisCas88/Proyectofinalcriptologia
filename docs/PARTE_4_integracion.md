# Parte 4: Seguridad, integración y documentación
Responsable: Santiago (análisis de seguridad e integración)

## Ya hecho
- `attacks/_lab.py`: laboratorio reproducible (servidor real en localhost, BD temporal, credenciales aleatorias por ejecución).
- Ataques 1 a 5 implementados y pasando: `python attacks/run_all.py` guarda los logs en `attacks/evidence/`.
- `tests/test_e2e.py`: flujo completo con entrega a usuario desconectado.
- `scripts/check_no_secrets.py`: busca secretos en el árbol y en todo el historial de Git.
- `Dockerfile`, `docker-compose.yml` (con `.dockerignore`, usuario no-root, healthcheck y servicios server/client/tests/attacks), `.gitignore`, `.env.example`, `README.md`.

## Pendientes
**Prioridad alta**
- [ ] Probar `docker compose up` y `docker compose --profile attacks run --rm attacks` en una máquina limpia y corregir lo que falle.
- [ ] Hacer una guía de commits: que los 4 integrantes tengan aportes reales desde el primer día.
- [ ] Ejecutar `python scripts/check_no_secrets.py` antes de cada push.
- [ ] Tomar las capturas de pantalla de los ataques (y Wireshark mostrando que el contenido va cifrado).

**Prioridad media**
- [ ] Implementar el ataque 6 (`attack_06_forward_secrecy.py`) con dos clientes reales.
- [ ] Informe técnico E4 (máx. 15 páginas, formato IEEE): introducción, modelo de amenazas, diseño criptográfico justificado, implementación, pruebas de ataque con evidencias, limitaciones, conclusiones, referencias.
- [ ] Guion y grabación del video E6 (máx. 8 minutos): recorrido funcional + los ataques fallidos.
- [ ] Presentación de la sustentación y banco de preguntas individuales para los 4.
- [ ] Integración continua opcional (GitHub Actions ejecutando `pytest` y los ataques).
