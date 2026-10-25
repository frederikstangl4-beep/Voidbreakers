#!/usr/bin/env python3
"""
Voidbreakers server: accounts, profiles, cloud saves, leaderboards and rooms.

Zero third-party dependencies beyond `websockets` (stdlib for everything else).

Run (dev):
    python3 server.py --host 0.0.0.0 --port 8765 --db data/voidbreakers.db

Run (public, TLS terminated here):
    python3 server.py --host 0.0.0.0 --port 8765 --cert fullchain.pem --key privkey.pem

Create a user from the console:
    python3 server.py --create-user Alice --password 'hunter2hunter2'
Reset a password:
    python3 server.py --reset-password Alice --password 'newpassword1'
"""
import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import string
import time

import websockets
from websockets.exceptions import ConnectionClosed

PROTOCOL_VERSION = 1
SERVER_NAME = "voidbreakers"

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SALT_BYTES = 16

TOKEN_BYTES = 32
SESSION_TTL = 30 * 24 * 3600

MAX_MESSAGE = 6 * 1024 * 1024  # frame cap; per-op limits below are tighter
PROFILE_MAX = 64 * 1024
SAVE_MAX = 5 * 1024 * 1024
SAVES_PER_USER = 5

ROOM_TTL = 6 * 3600
ROOM_MAX_MEMBERS = 8
ROOM_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ROOM_CODE_LEN = 5

AUTH_WINDOW = 300
AUTH_MAX_ATTEMPTS = 10
MSG_RATE_PER_SEC = 25
MAX_CONNECTIONS_PER_USER = 3
MAX_CONNECTIONS_TOTAL = 512

USERNAME_RE = None  # compiled below without re import cost concerns
USERNAME_MIN = 3
USERNAME_MAX = 16
PASSWORD_MIN = 8
PASSWORD_MAX = 200

BOARD_MODES = {
    "waves": 100000,
    "rift": 100000,
    "bossrush": 100000,
    "elo": 100000,
    "ghost": 100000,
}

log = logging.getLogger("voidbreakers")


# --------------------------------------------------------------------------- db

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  salt BLOB NOT NULL,
  hash BLOB NOT NULL,
  params TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_login INTEGER,
  recovery_salt BLOB,
  recovery_hash BLOB
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_ip TEXT
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id INTEGER PRIMARY KEY,
  meta_json TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS saves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  slot INTEGER NOT NULL,
  name TEXT,
  data TEXT NOT NULL,
  size INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, slot)
);
CREATE TABLE IF NOT EXISTS boards (
  mode TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  score INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (mode, user_id)
);
CREATE TABLE IF NOT EXISTS attempts (
  k TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS power_board (
  user_id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  score INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_boards_mode_score ON boards (mode, score DESC);
CREATE INDEX IF NOT EXISTS idx_power_board_score ON power_board (score DESC);
CREATE INDEX IF NOT EXISTS idx_saves_user ON saves (user_id);
"""


class Database:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = asyncio.Lock()
        with self.conn:
            self.conn.executescript(SCHEMA)

    async def run(self, fn, *args):
        async with self.lock:
            cur = self.conn.execute(fn, args)
            self.conn.commit()
            return cur

    async def one(self, sql, *args):
        async with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.fetchone()

    async def all(self, sql, *args):
        async with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.fetchall()


# ------------------------------------------------------------------------- auth

def scrypt_hash(password, salt=None):
    salt = salt or secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    params = "scrypt$%d$%d$%d" % (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return salt, digest, params


def verify_hash(password, salt, digest, params):
    try:
        kind, n, r, p = params.split("$")
        if kind != "scrypt":
            return False
        cand = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=int(n), r=int(r), p=int(p), dklen=len(digest),
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(cand, digest)
    except Exception:
        return False


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def valid_username(name):
    if not isinstance(name, str):
        return False
    if not (USERNAME_MIN <= len(name) <= USERNAME_MAX):
        return False
    for ch in name:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True


def valid_password(pw):
    return isinstance(pw, str) and PASSWORD_MIN <= len(pw) <= PASSWORD_MAX


def make_recovery_codes(count=4):
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(ROOM_CODE_ALPHABET) for _ in range(10))
        codes.append(raw[:5] + "-" + raw[5:])
    return codes


def normalize_recovery(code):
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def client_ip(ws):
    try:
        peer = ws.remote_address
        if peer:
            return str(peer[0])
    except Exception:
        pass
    return "unknown"


# ------------------------------------------------------------------------- state

class Server:
    def __init__(self, db, *, allow_origins=None):
        self.db = db
        self.allow_origins = allow_origins or []
        self.rooms = {}
        self.ws_state = {}
        self.user_connections = {}
        self.connections = 0
        self.attempt_cache = {}

    # ---- rate limits ----
    def rate_limited(self, key, limit, window):
        now = time.time()
        entry = self.attempt_cache.get(key)
        if entry and now - entry[1] > window:
            entry = None
        if entry is None:
            entry = [0, now]
        entry[0] += 1
        self.attempt_cache[key] = entry
        if len(self.attempt_cache) > 5000:
            for k in list(self.attempt_cache.keys())[:1000]:
                self.attempt_cache.pop(k, None)
        return entry[0] > limit

    async def send(self, ws, obj):
        try:
            await ws.send(json.dumps(obj))
        except Exception:
            pass

    def user_of(self, ws):
        st = self.ws_state.get(ws)
        return st.get("user") if st else None

    async def session_user(self, token):
        if not isinstance(token, str) or len(token) < 16:
            return None
        row = await self.db.one(
            "SELECT s.user_id, s.expires_at, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            token_hash(token),
        )
        if not row:
            return None
        if row["expires_at"] < int(time.time()):
            await self.db.run("DELETE FROM sessions WHERE token_hash = ?", token_hash(token))
            return None
        return {"id": row["user_id"], "username": row["username"]}

    async def issue_session(self, user_id, ws):
        token = secrets.token_urlsafe(TOKEN_BYTES)
        now = int(time.time())
        await self.db.run(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_ip) VALUES (?,?,?,?,?)",
            token_hash(token), user_id, now, now + SESSION_TTL, client_ip(ws),
        )
        return token

    async def touch_user(self, user_id, ws):
        await self.db.run("UPDATE users SET last_login = ? WHERE id = ?", int(time.time()), user_id)
        st = self.ws_state.setdefault(ws, {})
        st["session_count"] = st.get("session_count", 0) + 1

    # ---- handler ----
    async def handler(self, ws, path=None):
        self.connections += 1
        if self.connections > MAX_CONNECTIONS_TOTAL:
            await ws.close(code=1013, reason="server busy")
            self.connections -= 1
            return
        self.ws_state[ws] = {"user": None, "room": None, "msg_window": [time.time(), 0]}
        try:
            await self.send(ws, {"op": "welcome", "protocol": PROTOCOL_VERSION, "server": SERVER_NAME, "time": int(time.time())})
            async for raw in ws:
                if not isinstance(raw, str):
                    continue
                if len(raw) > MAX_MESSAGE:
                    await self.send(ws, {"op": "error", "code": "TOO_LARGE", "message": "Message too large."})
                    continue
                now = time.time()
                st = self.ws_state.get(ws)
                win = st.setdefault("msg_window", [now, 0])
                if now - win[0] >= 1:
                    win[0] = now
                    win[1] = 0
                win[1] += 1
                if win[1] > MSG_RATE_PER_SEC:
                    await ws.close(code=1008, reason="rate limit")
                    break
                try:
                    msg = json.loads(raw)
                except Exception:
                    await self.send(ws, {"op": "error", "code": "BAD_JSON", "message": "Invalid JSON."})
                    continue
                if not isinstance(msg, dict):
                    continue
                try:
                    await self.dispatch(ws, msg)
                except ConnectionClosed:
                    break
                except Exception:
                    log.exception("dispatch error for op=%s", msg.get("op"))
                    await self.send(ws, {"op": "error", "code": "SERVER_ERROR", "message": "Server error."})
        except ConnectionClosed:
            pass
        finally:
            await self.cleanup(ws)
            self.connections -= 1

    async def cleanup(self, ws):
        st = self.ws_state.pop(ws, None)
        if st and st.get("room"):
            await self.room_leave(ws)
        if st and st.get("user"):
            uid = st["user"]["id"]
            bucket = self.user_connections.get(uid)
            if bucket:
                bucket.discard(ws)
                if not bucket:
                    self.user_connections.pop(uid, None)

    async def dispatch(self, ws, msg):
        op = msg.get("op")
        if op == "register":
            return await self.op_register(ws, msg)
        if op == "login":
            return await self.op_login(ws, msg)
        if op == "resume":
            return await self.op_resume(ws, msg)
        if op == "logout":
            return await self.op_logout(ws, msg)
        if op == "password.change":
            return await self.op_password_change(ws, msg)
        if op == "recover":
            return await self.op_recover(ws, msg)
        if op == "profile.get":
            return await self.op_profile_get(ws, msg)
        if op == "profile.put":
            return await self.op_profile_put(ws, msg)
        if op == "save.list":
            return await self.op_save_list(ws, msg)
        if op == "save.push":
            return await self.op_save_push(ws, msg)
        if op == "save.pull":
            return await self.op_save_pull(ws, msg)
        if op == "save.delete":
            return await self.op_save_delete(ws, msg)
        if op == "board.top":
            return await self.op_board_top(ws, msg)
        if op == "board.submit":
            return await self.op_board_submit(ws, msg)
        if op == "power.top":
            return await self.op_power_top(ws, msg)
        if op == "power.submit":
            return await self.op_power_submit(ws, msg)
        if op == "room.create":
            return await self.op_room_create(ws, msg)
        if op == "room.join":
            return await self.op_room_join(ws, msg)
        if op == "room.leave":
            return await self.room_leave(ws, notify=True)
        if op == "room.signal":
            return await self.op_room_signal(ws, msg)
        if op == "room.list":
            return await self.send(ws, {"op": "rooms", "rooms": [
                {"code": r["code"], "members": len(r["members"]), "mode": r.get("mode", "coop")}
                for r in self.rooms.values()
            ]})
        if op == "chat.send":
            return await self.op_chat(ws, msg)
        if op == "ping":
            return await self.send(ws, {"op": "pong", "time": int(time.time())})
        await self.send(ws, {"op": "error", "code": "UNKNOWN_OP", "message": "Unknown op: %s" % op})

    # ---- auth ops ----
    async def op_register(self, ws, msg):
        ip = client_ip(ws)
        username = (msg.get("username") or "").strip()
        password = msg.get("password") or ""
        if self.rate_limited("reg:" + ip, AUTH_MAX_ATTEMPTS, AUTH_WINDOW):
            return await self.send(ws, {"op": "error", "code": "RATE_LIMIT", "message": "Too many attempts. Try again later."})
        if not valid_username(username):
            return await self.send(ws, {"op": "error", "code": "BAD_USERNAME", "message": "Username must be 3-16 letters, numbers or _."})
        if not valid_password(password):
            return await self.send(ws, {"op": "error", "code": "BAD_PASSWORD", "message": "Password must be at least %d characters." % PASSWORD_MIN})
        existing = await self.db.one("SELECT id FROM users WHERE username = ?", username)
        if existing:
            return await self.send(ws, {"op": "error", "code": "USERNAME_TAKEN", "message": "That username is already taken."})
        salt, digest, params = scrypt_hash(password)
        rec_codes = make_recovery_codes()
        rec_norm = normalize_recovery(rec_codes[0])
        rec_salt, rec_hash, _ = scrypt_hash(rec_norm)
        now = int(time.time())
        await self.db.run(
            "INSERT INTO users (username, salt, hash, params, created_at, recovery_salt, recovery_hash) VALUES (?,?,?,?,?,?,?)",
            username, salt, digest, params, now, rec_salt, rec_hash,
        )
        row = await self.db.one("SELECT id, username, created_at FROM users WHERE username = ?", username)
        await self.db.run("INSERT OR IGNORE INTO profiles (user_id, meta_json, updated_at) VALUES (?, '{}', ?)", row["id"], now)
        token = await self.issue_session(row["id"], ws)
        st = self.ws_state.setdefault(ws, {})
        st["user"] = {"id": row["id"], "username": row["username"]}
        self.user_connections.setdefault(row["id"], set()).add(ws)
        await self.send(ws, {
            "op": "session", "token": token,
            "user": {"id": row["id"], "username": row["username"], "createdAt": row["created_at"]},
            "recovery": rec_codes,
            "message": "Account created. Save your recovery codes - they are shown only once.",
        })

    async def op_login(self, ws, msg):
        ip = client_ip(ws)
        username = (msg.get("username") or "").strip()
        password = msg.get("password") or ""
        rl_key = "login:%s:%s" % (ip, username.lower())
        if self.rate_limited(rl_key, AUTH_MAX_ATTEMPTS, AUTH_WINDOW):
            return await self.send(ws, {"op": "error", "code": "RATE_LIMIT", "message": "Too many attempts. Try again later."})
        row = await self.db.one("SELECT * FROM users WHERE username = ?", username)
        if not row or not verify_hash(password, row["salt"], row["hash"], row["params"]):
            return await self.send(ws, {"op": "error", "code": "BAD_CREDENTIALS", "message": "Invalid username or password."})
        uid = row["id"]
        bucket = self.user_connections.setdefault(uid, set())
        if len(bucket) >= MAX_CONNECTIONS_PER_USER:
            return await self.send(ws, {"op": "error", "code": "TOO_MANY_SESSIONS", "message": "Too many open sessions for this account."})
        token = await self.issue_session(uid, ws)
        st = self.ws_state.setdefault(ws, {})
        st["user"] = {"id": uid, "username": row["username"]}
        bucket.add(ws)
        await self.touch_user(uid, ws)
        await self.send(ws, {"op": "session", "token": token, "user": {"id": uid, "username": row["username"], "createdAt": row["created_at"]}})

    async def op_resume(self, ws, msg):
        user = await self.session_user(msg.get("token"))
        if not user:
            return await self.send(ws, {"op": "error", "code": "BAD_TOKEN", "message": "Session expired. Log in again."})
        bucket = self.user_connections.setdefault(user["id"], set())
        if len(bucket) >= MAX_CONNECTIONS_PER_USER:
            return await self.send(ws, {"op": "error", "code": "TOO_MANY_SESSIONS", "message": "Too many open sessions for this account."})
        bucket.add(ws)
        st = self.ws_state.setdefault(ws, {})
        st["user"] = user
        token = await self.issue_session(user["id"], ws)
        await self.send(ws, {"op": "session", "token": token, "user": {"id": user["id"], "username": user["username"]}})

    async def op_logout(self, ws, msg):
        token = msg.get("token")
        if isinstance(token, str) and token:
            await self.db.run("DELETE FROM sessions WHERE token_hash = ?", token_hash(token))
        st = self.ws_state.get(ws)
        if st:
            st["user"] = None
        await self.send(ws, {"op": "ok", "for": "logout"})

    async def op_password_change(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        old_pw = msg.get("old") or ""
        new_pw = msg.get("new") or ""
        row = await self.db.one("SELECT * FROM users WHERE id = ?", user["id"])
        if not row or not verify_hash(old_pw, row["salt"], row["hash"], row["params"]):
            return await self.send(ws, {"op": "error", "code": "BAD_CREDENTIALS", "message": "Current password is wrong."})
        if not valid_password(new_pw):
            return await self.send(ws, {"op": "error", "code": "BAD_PASSWORD", "message": "Password must be at least %d characters." % PASSWORD_MIN})
        salt, digest, params = scrypt_hash(new_pw)
        await self.db.run("UPDATE users SET salt = ?, hash = ?, params = ? WHERE id = ?", salt, digest, params, user["id"])
        await self.db.run("DELETE FROM sessions WHERE user_id = ?", user["id"])
        token = await self.issue_session(user["id"], ws)
        await self.send(ws, {"op": "ok", "for": "password.change", "token": token})

    async def op_recover(self, ws, msg):
        ip = client_ip(ws)
        if self.rate_limited("recover:" + ip, AUTH_MAX_ATTEMPTS, AUTH_WINDOW):
            return await self.send(ws, {"op": "error", "code": "RATE_LIMIT", "message": "Too many attempts. Try again later."})
        username = (msg.get("username") or "").strip()
        code = normalize_recovery(msg.get("code"))
        new_pw = msg.get("newPassword") or ""
        row = await self.db.one("SELECT * FROM users WHERE username = ?", username)
        ok = False
        if row and row["recovery_hash"] and code:
            ok = verify_hash(code, row["recovery_salt"], row["recovery_hash"], row["params"])
        if not ok:
            return await self.send(ws, {"op": "error", "code": "BAD_CREDENTIALS", "message": "Invalid username or recovery code."})
        if not valid_password(new_pw):
            return await self.send(ws, {"op": "error", "code": "BAD_PASSWORD", "message": "Password must be at least %d characters." % PASSWORD_MIN})
        salt, digest, params = scrypt_hash(new_pw)
        new_codes = make_recovery_codes()
        rec_salt, rec_hash, _ = scrypt_hash(normalize_recovery(new_codes[0]))
        await self.db.run(
            "UPDATE users SET salt = ?, hash = ?, params = ?, recovery_salt = ?, recovery_hash = ? WHERE id = ?",
            salt, digest, params, rec_salt, rec_hash, row["id"],
        )
        await self.db.run("DELETE FROM sessions WHERE user_id = ?", row["id"])
        await self.send(ws, {"op": "ok", "for": "recover", "recovery": new_codes})

    # ---- profile ----
    async def op_profile_get(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        row = await self.db.one("SELECT meta_json, updated_at FROM profiles WHERE user_id = ?", user["id"])
        meta = row["meta_json"] if row else "{}"
        await self.send(ws, {"op": "profile", "meta": json.loads(meta or "{}"), "updatedAt": row["updated_at"] if row else 0})

    async def op_profile_put(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        meta = msg.get("meta")
        if not isinstance(meta, dict):
            return await self.send(ws, {"op": "error", "code": "BAD_META", "message": "meta must be an object."})
        blob = json.dumps(meta, separators=(",", ":"))
        if len(blob) > PROFILE_MAX:
            return await self.send(ws, {"op": "error", "code": "META_TOO_LARGE", "message": "Profile too large."})
        now = int(time.time())
        await self.db.run(
            "INSERT INTO profiles (user_id, meta_json, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET meta_json = excluded.meta_json, updated_at = excluded.updated_at",
            user["id"], blob, now,
        )
        await self.send(ws, {"op": "ok", "for": "profile.put", "updatedAt": now})

    # ---- saves ----
    async def op_save_list(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        rows = await self.db.all("SELECT slot, name, size, updated_at FROM saves WHERE user_id = ? ORDER BY slot", user["id"])
        await self.send(ws, {"op": "saves", "saves": [dict(r) for r in rows]})

    async def op_save_push(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        slot = msg.get("slot")
        data = msg.get("data")
        name = str(msg.get("name") or "World")[:40]
        if not isinstance(slot, int) or slot < 0 or slot >= SAVES_PER_USER:
            return await self.send(ws, {"op": "error", "code": "BAD_SLOT", "message": "Invalid slot."})
        if not isinstance(data, str) or len(data) > SAVE_MAX:
            return await self.send(ws, {"op": "error", "code": "SAVE_TOO_LARGE", "message": "Save too large."})
        now = int(time.time())
        await self.db.run(
            "INSERT INTO saves (user_id, slot, name, data, size, updated_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(user_id, slot) DO UPDATE SET name = excluded.name, data = excluded.data, size = excluded.size, updated_at = excluded.updated_at",
            user["id"], slot, name, data, len(data), now,
        )
        await self.send(ws, {"op": "ok", "for": "save.push", "slot": slot, "size": len(data), "updatedAt": now})

    async def op_save_pull(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        slot = msg.get("slot")
        if not isinstance(slot, int):
            return await self.send(ws, {"op": "error", "code": "BAD_SLOT", "message": "Invalid slot."})
        row = await self.db.one("SELECT slot, name, data, size, updated_at FROM saves WHERE user_id = ? AND slot = ?", user["id"], slot)
        if not row:
            return await self.send(ws, {"op": "error", "code": "NO_SAVE", "message": "No cloud save in that slot."})
        await self.send(ws, {"op": "save", "slot": row["slot"], "name": row["name"], "data": row["data"], "size": row["size"], "updatedAt": row["updated_at"]})

    async def op_save_delete(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        slot = msg.get("slot")
        await self.db.run("DELETE FROM saves WHERE user_id = ? AND slot = ?", user["id"], slot)
        await self.send(ws, {"op": "ok", "for": "save.delete", "slot": slot})

    # ---- boards ----
    async def op_board_top(self, ws, msg):
        mode = msg.get("mode")
        if mode not in BOARD_MODES:
            return await self.send(ws, {"op": "error", "code": "BAD_MODE", "message": "Unknown board."})
        limit = max(1, min(100, int(msg.get("limit") or 10)))
        rows = await self.db.all(
            "SELECT u.username, b.score, b.updated_at FROM boards b JOIN users u ON u.id = b.user_id "
            "WHERE b.mode = ? ORDER BY b.score DESC, b.updated_at ASC LIMIT ?",
            mode, limit,
        )
        await self.send(ws, {"op": "board", "mode": mode, "entries": [dict(r) for r in rows]})

    async def op_board_submit(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        mode = msg.get("mode")
        if mode not in BOARD_MODES:
            return await self.send(ws, {"op": "error", "code": "BAD_MODE", "message": "Unknown board."})
        try:
            score = int(msg.get("score"))
        except Exception:
            return await self.send(ws, {"op": "error", "code": "BAD_SCORE", "message": "Score must be a number."})
        cap = BOARD_MODES[mode]
        if score < 0 or score > cap:
            return await self.send(ws, {"op": "error", "code": "SCORE_OUT_OF_RANGE", "message": "Score out of range."})
        now = int(time.time())
        row = await self.db.one("SELECT score FROM boards WHERE mode = ? AND user_id = ?", mode, user["id"])
        if row and row["score"] >= score:
            return await self.send(ws, {"op": "ok", "for": "board.submit", "best": row["score"]})
        await self.db.run(
            "INSERT INTO boards (mode, user_id, score, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(mode, user_id) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at",
            mode, user["id"], score, now,
        )
        rank = await self.db.one("SELECT COUNT(*) + 1 AS r FROM boards WHERE mode = ? AND score > ?", mode, score)
        await self.send(ws, {"op": "ok", "for": "board.submit", "best": score, "rank": rank["r"] if rank else None})

    async def op_power_top(self, ws, msg):
        limit = max(1, min(50, int(msg.get("limit") or 20)))
        rows = await self.db.all(
            "SELECT name, score, updated_at FROM power_board ORDER BY score DESC, updated_at ASC LIMIT ?",
            limit,
        )
        await self.send(ws, {"op": "power", "entries": [dict(r) for r in rows]})

    async def op_power_submit(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        raw = str(msg.get("name") or "").strip()[:24]
        name = "".join(ch for ch in raw if ch.isprintable() and ch not in "<>\n\r\t")
        if len(name) < 2:
            return await self.send(ws, {"op": "error", "code": "BAD_NAME", "message": "Player name too short."})
        try:
            score = int(msg.get("score"))
        except Exception:
            return await self.send(ws, {"op": "error", "code": "BAD_SCORE", "message": "Score must be a number."})
        if score < 0 or score > 1000000000000:
            return await self.send(ws, {"op": "error", "code": "SCORE_OUT_OF_RANGE", "message": "Score out of range."})
        now = int(time.time())
        row = await self.db.one("SELECT score FROM power_board WHERE user_id = ?", user["id"])
        if row and row["score"] >= score:
            await self.db.run("UPDATE power_board SET name = ? WHERE user_id = ?", name, user["id"])
            return await self.send(ws, {"op": "ok", "for": "power.submit", "best": row["score"]})
        await self.db.run(
            "INSERT INTO power_board (user_id, name, score, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET name = excluded.name, score = excluded.score, updated_at = excluded.updated_at",
            user["id"], name, score, now,
        )
        rank = await self.db.one("SELECT COUNT(*) + 1 AS r FROM power_board WHERE score > ?", score)
        await self.send(ws, {"op": "ok", "for": "power.submit", "best": score, "rank": rank["r"] if rank else None})

    # ---- rooms ----
    def new_room_code(self):
        for _ in range(50):
            code = "".join(secrets.choice(ROOM_CODE_ALPHABET) for _ in range(ROOM_CODE_LEN))
            if code not in self.rooms:
                return code
        raise RuntimeError("no room codes left")

    async def op_room_create(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        await self.room_leave(ws, notify=False)
        code = self.new_room_code()
        self.rooms[code] = {
            "code": code, "host": user["id"], "members": {ws: user},
            "created": time.time(), "mode": str(msg.get("mode") or "coop")[:20],
        }
        st = self.ws_state.setdefault(ws, {})
        st["room"] = code
        await self.send(ws, {"op": "room.created", "code": code, "members": 1})
        log.info("room %s created by %s", code, user["username"])

    async def op_room_join(self, ws, msg):
        user = self.user_of(ws)
        if not user:
            return await self.send(ws, {"op": "error", "code": "NOT_LOGGED_IN", "message": "Log in first."})
        code = str(msg.get("code") or "").strip().upper()
        room = self.rooms.get(code)
        if not room:
            return await self.send(ws, {"op": "error", "code": "NO_ROOM", "message": "Room not found."})
        if len(room["members"]) >= ROOM_MAX_MEMBERS:
            return await self.send(ws, {"op": "error", "code": "ROOM_FULL", "message": "Room is full."})
        await self.room_leave(ws, notify=False)
        room["members"][ws] = user
        st = self.ws_state.setdefault(ws, {})
        st["room"] = code
        await self.send(ws, {"op": "room.joined", "code": code, "members": len(room["members"]),
                            "peers": [{"id": u["id"], "username": u["username"]} for w, u in room["members"].items() if w is not ws]})
        for peer_ws in list(room["members"].keys()):
            if peer_ws is not ws:
                await self.send(peer_ws, {"op": "room.peer", "event": "joined", "user": {"id": user["id"], "username": user["username"]}})
        log.info("room %s joined by %s", code, user["username"])

    async def room_leave(self, ws, notify=False):
        st = self.ws_state.get(ws)
        if not st or not st.get("room"):
            if notify:
                await self.send(ws, {"op": "ok", "for": "room.leave"})
            return
        code = st["room"]
        st["room"] = None
        room = self.rooms.get(code)
        user = st.get("user")
        if room and ws in room["members"]:
            del room["members"][ws]
            for peer_ws in list(room["members"].keys()):
                await self.send(peer_ws, {"op": "room.peer", "event": "left", "user": user})
            if not room["members"]:
                self.rooms.pop(code, None)
        if notify:
            await self.send(ws, {"op": "ok", "for": "room.leave"})

    async def op_room_signal(self, ws, msg):
        st = self.ws_state.get(ws)
        room = self.rooms.get(st.get("room")) if st and st.get("room") else None
        if not room:
            return await self.send(ws, {"op": "error", "code": "NOT_IN_ROOM", "message": "Join a room first."})
        payload = msg.get("data")
        if payload is None:
            return
        blob = json.dumps(payload)
        if len(blob) > 32 * 1024:
            return await self.send(ws, {"op": "error", "code": "SIGNAL_TOO_LARGE", "message": "Signal too large."})
        for peer_ws in list(room["members"].keys()):
            if peer_ws is not ws:
                await self.send(peer_ws, {"op": "room.signal", "from": st["user"]["id"], "data": payload})

    async def op_chat(self, ws, msg):
        st = self.ws_state.get(ws)
        room = self.rooms.get(st.get("room")) if st and st.get("room") else None
        if not room:
            return await self.send(ws, {"op": "error", "code": "NOT_IN_ROOM", "message": "Join a room first."})
        text = str(msg.get("text") or "")[:200]
        if not text.strip():
            return
        for peer_ws in list(room["members"].keys()):
            if peer_ws is ws:
                continue
            await self.send(peer_ws, {"op": "chat", "from": st["user"]["username"], "text": text, "time": int(time.time())})

    # ---- maintenance ----
    async def reaper(self):
        while True:
            await asyncio.sleep(600)
            now = time.time()
            for code in list(self.rooms.keys()):
                room = self.rooms[code]
                if not room["members"] or now - room["created"] > ROOM_TTL:
                    self.rooms.pop(code, None)
            async with self.db.lock:
                self.db.conn.execute("DELETE FROM sessions WHERE expires_at < ?", (int(now),))
                self.db.conn.execute("DELETE FROM attempts WHERE ts < ?", (int(now) - 3600,))
                self.db.conn.commit()


# ------------------------------------------------------------------------ main

async def amain(args):
    db = Database(args.db)
    server = Server(db, allow_origins=args.allow_origin)

    async def health(path, headers):
        if path in ("/healthz", "/health"):
            body = json.dumps({"ok": True, "rooms": len(server.rooms), "connections": server.connections})
            return 200, [("Content-Type", "application/json")], body.encode()
        return None

    extra = {}
    if args.cert and args.key:
        extra["ssl"] = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_SERVER)
        extra["ssl"].load_cert_chain(args.cert, args.key)
    async with websockets.serve(server.handler, args.host, args.port, process_request=health, max_size=MAX_MESSAGE + 4096, **extra):
        log.info("%s protocol v%d listening on %s:%d%s", SERVER_NAME, PROTOCOL_VERSION, args.host, args.port,
                 " (TLS)" if extra else "")
        await server.reaper()


def admin_create_user(args):
    db = Database(args.db)
    username = args.create_user
    password = args.password or ""
    if not valid_username(username):
        print("Invalid username (3-16 letters/numbers/_).")
        return 1
    if not valid_password(password):
        print("Password must be at least %d characters." % PASSWORD_MIN)
        return 1
    row = db.conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        print("User already exists.")
        return 1
    salt, digest, params = scrypt_hash(password)
    codes = make_recovery_codes()
    rec_salt, rec_hash, _ = scrypt_hash(normalize_recovery(codes[0]))
    now = int(time.time())
    with db.conn:
        db.conn.execute(
            "INSERT INTO users (username, salt, hash, params, created_at, recovery_salt, recovery_hash) VALUES (?,?,?,?,?,?,?)",
            (username, salt, digest, params, now, rec_salt, rec_hash),
        )
        uid = db.conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        db.conn.execute("INSERT OR IGNORE INTO profiles (user_id, meta_json, updated_at) VALUES (?, '{}', ?)", (uid, now))
    print("Created %s (id %d). Recovery code: %s" % (username, uid, codes[0]))
    return 0


def admin_reset_password(args):
    db = Database(args.db)
    username = args.reset_password
    password = args.password or ""
    if not valid_password(password):
        print("Password must be at least %d characters." % PASSWORD_MIN)
        return 1
    row = db.conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        print("No such user.")
        return 1
    salt, digest, params = scrypt_hash(password)
    with db.conn:
        db.conn.execute("UPDATE users SET salt = ?, hash = ?, params = ? WHERE id = ?", (salt, digest, params, row["id"]))
        db.conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
    print("Password reset for %s." % username)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Voidbreakers game server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="data/voidbreakers.db")
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--allow-origin", action="append", default=None, help="Allowed Origin header (repeatable). Default: allow all.")
    parser.add_argument("--create-user", default=None)
    parser.add_argument("--reset-password", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.create_user:
        return admin_create_user(args)
    if args.reset_password:
        return admin_reset_password(args)
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
