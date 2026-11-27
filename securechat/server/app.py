"""API REST del servidor.

Endpoints:  POST /register   POST /login   GET /bundle/{user}   POST /messages   GET /messages
Notas de seguridad:
  * Contraseñas: Argon2id con sal (securechat.crypto.kdf). Nunca se guarda ni se registra la contraseña.
  * Tokens de sesión: 256 bits aleatorios (secrets), expiran, se guardan como SHA-256.
  * Un usuario solo lee su propio buzón (Elevation of privilege).
  * La confidencialidad del contenido NO depende de TLS ni de este servidor.
"""
import hashlib
import json
import secrets
import time
from collections import defaultdict

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from securechat.crypto.encoding import b64d
from securechat.crypto.kdf import hash_password, verify_password
from securechat.crypto.keys import BundleSignatureError, PreKeyBundle, verify_bundle

from .db import connect, init_db

TOKEN_TTL_SECONDS = 3600  # 1 hora (tabla de parámetros del E1)
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
_failed: dict[str, list[float]] = defaultdict(list)  # TODO Parte 2: persistir / limitar por IP también

app = FastAPI(title="SecureChat server")


@app.on_event("startup")
def _startup() -> None:
    init_db()


# ---------- modelos ----------
class BundleIn(BaseModel):
    ik_sig_pub: str
    ik_dh_pub: str
    spk_pub: str
    sig_spk: str


class RegisterIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,32}$")
    password: str = Field(min_length=10, max_length=256)
    bundle: BundleIn


class LoginIn(BaseModel):
    username: str
    password: str


class MessageIn(BaseModel):
    to: str
    init: dict | None = None  # {"ik_sig_pub","ik_dh_pub","ek_pub"} solo en mensajes iniciales
    n: int = Field(ge=0)
    ciphertext: str


# ---------- autenticación ----------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "falta el token")
    th = _hash_token(authorization[7:])
    with connect() as conn:
        row = conn.execute("SELECT username, expires FROM sessions WHERE token_hash=?", (th,)).fetchone()
    if not row or row["expires"] < time.time():
        raise HTTPException(401, "token inválido o expirado")
    return row["username"]


# ---------- endpoints ----------
@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register", status_code=201)
def register(body: RegisterIn):
    bundle = PreKeyBundle.from_dict(body.bundle.model_dump())
    try:
        verify_bundle(bundle)  # el servidor tampoco acepta bundles mal firmados
    except BundleSignatureError:
        raise HTTPException(400, "bundle con firma inválida")
    salt, pw_hash = hash_password(body.password)
    with connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise HTTPException(409, "usuario ya existe")
        b = body.bundle
        conn.execute(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?,?)",
            (body.username, salt, pw_hash, b.ik_sig_pub, b.ik_dh_pub, b.spk_pub, b.sig_spk, time.time()),
        )
    return {"username": body.username}


@app.post("/login")
def login(body: LoginIn):
    now = time.time()
    _failed[body.username] = [t for t in _failed[body.username] if now - t < LOCKOUT_SECONDS]
    if len(_failed[body.username]) >= MAX_FAILED_LOGINS:
        raise HTTPException(429, "demasiados intentos; espere unos minutos")
    with connect() as conn:
        row = conn.execute("SELECT pw_salt, pw_hash FROM users WHERE username=?", (body.username,)).fetchone()
    if row is None:  # trabajo ficticio para no revelar si el usuario existe por tiempo de respuesta
        verify_password(body.password, b"\x00" * 16, b"\x00" * 32)
        ok = False
    else:
        ok = verify_password(body.password, row["pw_salt"], row["pw_hash"])
    if not ok:
        _failed[body.username].append(now)
        raise HTTPException(401, "credenciales inválidas")
    token = secrets.token_urlsafe(32)
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires < ?", (now,))
        conn.execute("INSERT INTO sessions VALUES (?,?,?)", (_hash_token(token), body.username, now + TOKEN_TTL_SECONDS))
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS}


@app.get("/bundle/{username}")
def get_bundle(username: str, _: str = Depends(current_user)):
    with connect() as conn:
        r = conn.execute(
            "SELECT ik_sig_pub, ik_dh_pub, spk_pub, sig_spk FROM users WHERE username=?", (username,)
        ).fetchone()
    if not r:
        raise HTTPException(404, "usuario no encontrado")
    return dict(r)


@app.post("/messages", status_code=201)
def send_message(body: MessageIn, me: str = Depends(current_user)):
    try:
        b64d(body.ciphertext)
    except Exception:
        raise HTTPException(400, "ciphertext no es base64")
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (body.to,)).fetchone():
            raise HTTPException(404, "destinatario no existe")
        conn.execute(
            "INSERT INTO messages (sender, recipient, init, n, ciphertext, ts) VALUES (?,?,?,?,?,?)",
            (me, body.to, json.dumps(body.init) if body.init else None, body.n, body.ciphertext, time.time()),
        )
    return {"queued": True}


@app.get("/messages")
def fetch_messages(me: str = Depends(current_user)):
    """Devuelve y elimina los mensajes pendientes del usuario autenticado.
    TODO Parte 2: cambiar a GET + POST /messages/ack para no perder mensajes si el cliente falla."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, sender, init, n, ciphertext, ts FROM messages WHERE recipient=? ORDER BY id", (me,)
        ).fetchall()
        conn.execute("DELETE FROM messages WHERE recipient=?", (me,))
    return [
        {"id": r["id"], "from": r["sender"], "init": json.loads(r["init"]) if r["init"] else None,
         "n": r["n"], "ciphertext": r["ciphertext"], "ts": r["ts"]}
        for r in rows
    ]
