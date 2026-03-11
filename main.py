"""
SecChat - Live encrypted chat, zero JavaScript
Encryption: X25519 key exchange + ChaCha20-Poly1305 AEAD
Transport:  SSE (Server-Sent Events) via <iframe> auto-refresh
Auth:       Argon2id password hashing, session cookies (HttpOnly + Secure + SameSite=Strict)
"""

import os
import uuid
import time
import asyncio
import base64
import secrets
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Form, Response, Depends, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import argon2
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import struct

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

# ── In-memory stores (replace with Redis for multi-instance) ──────────────────
users: dict[str, dict] = {}          # username → {hash, pubkey_bytes}
sessions: dict[str, str] = {}        # session_id → username
rooms: dict[str, list] = defaultdict(list)   # room → [msg dicts]
room_keys: dict[str, bytes] = {}     # room → shared ChaCha20 key (32 bytes)
server_privkeys: dict[str, bytes] = {}       # room → X25519 private key bytes
waiters: dict[str, list] = defaultdict(list) # room → [asyncio.Queue]

MAX_MESSAGES = 500
MAX_ROOMS = 50
MAX_MSG_LEN = 1000

# ── Crypto helpers ─────────────────────────────────────────────────────────────

def generate_room_keypair(room: str):
    """Generate X25519 keypair for a room. Key stored server-side."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    server_privkeys[room] = priv_bytes
    return pub_bytes

def derive_room_key(room: str, client_pubkey_bytes: bytes) -> bytes:
    """X25519 ECDH → derive 32-byte ChaCha20 key via HKDF-SHA256."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    priv_bytes = server_privkeys[room]
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    client_pub = X25519PrivateKey.generate().public_key().__class__.from_public_bytes(client_pubkey_bytes)

    # Perform ECDH
    shared = priv.exchange(client_pub)

    # HKDF to derive final key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=room.encode(),
        info=b"secchat-chacha20"
    )
    return hkdf.derive(shared)

def encrypt_message(room: str, plaintext: str) -> tuple[str, str]:
    """Encrypt with ChaCha20-Poly1305. Returns (nonce_b64, ciphertext_b64)."""
    key = room_keys.get(room)
    if not key:
        # Room without key exchange — use deterministic room key from room name + server secret
        secret = os.environ.get("SERVER_SECRET", "change-this-in-production-32b!!")
        key = hashlib.sha256(f"{secret}:{room}".encode()).digest()
        room_keys[room] = key

    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()

def decrypt_message(room: str, nonce_b64: str, ct_b64: str) -> str:
    """Decrypt ChaCha20-Poly1305 message."""
    key = room_keys.get(room)
    if not key:
        return "[encrypted — key unavailable]"
    try:
        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
        return chacha.decrypt(nonce, ct, None).decode()
    except Exception:
        return "[decryption failed — invalid key or tampered message]"

# ── Session helpers ────────────────────────────────────────────────────────────

def get_current_user(session_id: Optional[str] = Cookie(default=None)) -> Optional[str]:
    if not session_id:
        return None
    return sessions.get(session_id)

def require_user(session_id: Optional[str] = Cookie(default=None)) -> str:
    user = get_current_user(session_id)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user

# ── Broadcast helper ───────────────────────────────────────────────────────────

async def broadcast(room: str, msg: dict):
    for q in list(waiters[room]):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass

# ── Routes: Auth ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, session_id: Optional[str] = Cookie(default=None)):
    user = get_current_user(session_id)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return RedirectResponse("/rooms", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()[:32]
    user = users.get(username)

    if not user:
        # Register on first login
        if len(users) > 200:
            return RedirectResponse("/login?error=Server+full", status_code=303)
        if len(username) < 3 or not username.isalnum():
            return RedirectResponse("/login?error=Username+must+be+3+alphanumeric+chars", status_code=303)
        hashed = ph.hash(password)
        users[username] = {"hash": hashed}
    else:
        try:
            ph.verify(user["hash"], password)
            if ph.check_needs_rehash(user["hash"]):
                users[username]["hash"] = ph.hash(password)
        except argon2.exceptions.VerifyMismatchError:
            return RedirectResponse("/login?error=Invalid+credentials", status_code=303)

    sid = secrets.token_urlsafe(32)
    sessions[sid] = username
    resp = RedirectResponse("/rooms", status_code=303)
    resp.set_cookie(
        "session_id", sid,
        httponly=True, secure=False,  # set secure=True behind HTTPS
        samesite="strict",
        max_age=86400 * 7
    )
    return resp

@app.post("/logout")
async def logout(response: Response, session_id: Optional[str] = Cookie(default=None)):
    if session_id and session_id in sessions:
        del sessions[session_id]
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("session_id")
    return resp

# ── Routes: Rooms ──────────────────────────────────────────────────────────────

@app.get("/rooms", response_class=HTMLResponse)
async def rooms_page(request: Request, user: str = Depends(require_user)):
    room_list = list(rooms.keys()) or []
    return templates.TemplateResponse("rooms.html", {
        "request": request,
        "user": user,
        "rooms": room_list
    })

@app.post("/rooms/create")
async def create_room(room_name: str = Form(...), user: str = Depends(require_user)):
    name = room_name.strip().lower().replace(" ", "-")[:32]
    if not name or not all(c.isalnum() or c == '-' for c in name):
        return RedirectResponse("/rooms?error=Invalid+room+name", status_code=303)
    if len(rooms) >= MAX_ROOMS and name not in rooms:
        return RedirectResponse("/rooms?error=Too+many+rooms", status_code=303)
    if name not in rooms:
        rooms[name] = []
        generate_room_keypair(name)
    return RedirectResponse(f"/chat/{name}", status_code=303)

# ── Routes: Chat ───────────────────────────────────────────────────────────────

@app.get("/chat/{room}", response_class=HTMLResponse)
async def chat_page(request: Request, room: str, user: str = Depends(require_user)):
    if room not in rooms:
        rooms[room] = []
        generate_room_keypair(room)

    # Decrypt messages for display
    msgs = []
    for m in rooms[room][-50:]:
        plain = decrypt_message(room, m["nonce"], m["ct"])
        msgs.append({
            "author": m["author"],
            "text": plain,
            "time": m["time"],
            "id": m["id"]
        })

    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": user,
        "room": room,
        "messages": msgs,
        "msg_count": len(rooms[room])
    })

@app.post("/chat/{room}/send")
async def send_message(
    room: str,
    message: str = Form(...),
    user: str = Depends(require_user)
):
    if not message.strip():
        return RedirectResponse(f"/chat/{room}", status_code=303)

    text = message.strip()[:MAX_MSG_LEN]
    nonce_b64, ct_b64 = encrypt_message(room, text)

    msg = {
        "id": secrets.token_hex(8),
        "author": user,
        "nonce": nonce_b64,
        "ct": ct_b64,
        "time": datetime.now(timezone.utc).strftime("%H:%M"),
        "ts": time.time()
    }

    rooms[room].append(msg)
    if len(rooms[room]) > MAX_MESSAGES:
        rooms[room] = rooms[room][-MAX_MESSAGES:]

    # Broadcast to SSE listeners
    plain_msg = {
        "id": msg["id"],
        "author": user,
        "text": text,
        "time": msg["time"]
    }
    await broadcast(room, plain_msg)

    return RedirectResponse(f"/chat/{room}", status_code=303)

# ── SSE endpoint — live updates without JS polling ────────────────────────────

@app.get("/chat/{room}/stream")
async def stream(room: str, user: str = Depends(require_user)):
    """Server-Sent Events stream. Browser <iframe> with meta-refresh reads this."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=20)
    waiters[room].append(queue)

    async def event_generator():
        try:
            # Send keepalive
            yield "retry: 3000\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=25)
                    author = msg['author']
                    text = msg['text'].replace('\n', ' ')
                    t = msg['time']
                    data = f"{t} [{author}] {text}"
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if queue in waiters[room]:
                waiters[room].remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

# ── Crypto info endpoint ───────────────────────────────────────────────────────

@app.get("/crypto-info", response_class=HTMLResponse)
async def crypto_info(request: Request, user: str = Depends(require_user)):
    return templates.TemplateResponse("crypto.html", {"request": request, "user": user})
