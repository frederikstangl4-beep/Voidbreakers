#!/usr/bin/env python3
"""Integration tests for the Voidbreakers server. Run: python3 tests/test_client.py"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

import websockets

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = 8791
URL = "ws://127.0.0.1:%d" % PORT

PASS = 0
FAIL = 0


def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS", name, ("[%s]" % extra) if extra else "")
    else:
        FAIL += 1
        print("FAIL", name, ("[%s]" % extra) if extra else "")


class Client:
    def __init__(self, ws):
        self.ws = ws
        self.pending = []

    async def send(self, op, **kw):
        msg = {"op": op}
        msg.update(kw)
        await self.ws.send(json.dumps(msg))

    async def wait(self, op=None, timeout=5.0, pred=None):
        deadline = time.time() + timeout
        while True:
            for i, m in enumerate(self.pending):
                if (op is None or m.get("op") == op) and (pred is None or pred(m)):
                    return self.pending.pop(i)
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError("waiting for %s" % op)
            try:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=left)
            except asyncio.TimeoutError:
                raise TimeoutError("waiting for %s" % op)
            m = json.loads(raw)
            if m.get("op") == "pong" or m.get("op") == "welcome":
                if op is None or m.get("op") == op:
                    return m
                continue
            self.pending.append(m)

    async def call(self, op, **kw):
        await self.send(op, **kw)
        return await self.wait()


async def conn():
    ws = await websockets.connect(URL)
    c = Client(ws)
    await c.wait("welcome")
    return c


async def main():
    tmpdir = tempfile.mkdtemp(prefix="vb-test-")
    db_path = os.path.join(tmpdir, "test.db")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "server.py"), "--host", "127.0.0.1", "--port", str(PORT), "--db", db_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            try:
                c0 = await conn()
                await c0.ws.close()
                break
            except Exception:
                await asyncio.sleep(0.1)
        else:
            print("server did not start")
            return 1

        # register
        c = await conn()
        r = await c.call("register", username="Alice_1", password="hunter2hunter2")
        check("register returns session", r.get("op") == "session" and len(r.get("token", "")) > 20)
        check("register gives recovery codes", isinstance(r.get("recovery"), list) and len(r["recovery"]) == 4, r.get("recovery", [""])[0])
        token = r["token"]
        recovery = r["recovery"][0]

        # duplicate
        c2 = await conn()
        r = await c2.call("register", username="alice_1", password="hunter2hunter2")
        check("duplicate username rejected (case-insensitive)", r.get("code") == "USERNAME_TAKEN", r.get("code"))
        r = await c2.call("register", username="ab", password="hunter2hunter2")
        check("short username rejected", r.get("code") == "BAD_USERNAME")
        r = await c2.call("register", username="Bob_1", password="short")
        check("short password rejected", r.get("code") == "BAD_PASSWORD")

        # login + wrong password
        c3 = await conn()
        r = await c3.call("login", username="alice_1", password="wrongwrongwrong")
        check("wrong password rejected", r.get("code") == "BAD_CREDENTIALS", r.get("code"))
        r = await c3.call("login", username="alice_1", password="hunter2hunter2")
        check("login works", r.get("op") == "session", r.get("code", "ok"))
        token2 = r["token"]

        # resume
        c4 = await conn()
        r = await c4.call("resume", token=token)
        check("resume works", r.get("op") == "session" and r.get("user", {}).get("username") == "Alice_1")
        r = await c4.call("resume", token="not-a-real-token-at-all")
        check("bad token rejected", r.get("code") == "BAD_TOKEN")

        # profile
        r = await c4.call("profile.put", meta={"level": 7, "elo": 1234, "ach": {"firstwin": True}})
        check("profile put", r.get("op") == "ok")
        r = await c4.call("profile.get")
        check("profile get roundtrip", r.get("meta", {}).get("level") == 7 and r["meta"]["ach"]["firstwin"] is True, json.dumps(r.get("meta")))
        big = {"x": "a" * (70 * 1024)}
        r = await c4.call("profile.put", meta=big)
        check("oversized profile rejected", r.get("code") == "META_TOO_LARGE")

        # anonymous profile rejected
        anon = await conn()
        r = await anon.call("profile.get")
        check("anonymous profile rejected", r.get("code") == "NOT_LOGGED_IN")

        # saves
        r = await c4.call("save.push", slot=0, name="My World", data="b64data" * 10)
        check("save push", r.get("op") == "ok" and r.get("size") > 0)
        r = await c4.call("save.pull", slot=0)
        check("save pull roundtrip", r.get("data", "").startswith("b64data") and r.get("name") == "My World")
        r = await c4.call("save.list")
        check("save list", len(r.get("saves", [])) == 1)
        r = await c4.call("save.push", slot=9, data="x")
        check("bad slot rejected", r.get("code") == "BAD_SLOT")
        r = await c4.call("save.delete", slot=0)
        check("save delete", r.get("op") == "ok")
        r = await c4.call("save.pull", slot=0)
        check("deleted save gone", r.get("code") == "NO_SAVE")

        # boards
        r = await c4.call("board.submit", mode="waves", score=17)
        check("board submit", r.get("op") == "ok" and r.get("best") == 17, "rank=%s" % r.get("rank"))
        r = await c4.call("board.submit", mode="waves", score=9)
        check("board keeps best only", r.get("best") == 17)
        r = await c4.call("board.submit", mode="waves", score=99999999)
        check("board clamps impossible score", r.get("code") == "SCORE_OUT_OF_RANGE")
        r = await c4.call("board.top", mode="waves", limit=10)
        check("board top lists entry", len(r.get("entries", [])) == 1 and r["entries"][0]["score"] == 17)
        r = await c4.call("board.top", mode="nope")
        check("unknown board rejected", r.get("code") == "BAD_MODE")

        # rooms
        host = await conn()
        await host.call("register", username="Host_1", password="hostpass12345")
        r = await host.call("room.create", mode="coop")
        code = r.get("code")
        check("room created with 5-char code", isinstance(code, str) and len(code) == 5, code)

        guest = await conn()
        await guest.call("register", username="Guest_1", password="guestpass123")
        r = await guest.call("room.join", code=code)
        check("guest joined room", r.get("code") == code and len(r.get("peers", [])) == 1)
        r = await host.wait("room.peer")
        check("host notified of peer", r.get("event") == "joined" and r["user"]["username"] == "Guest_1")

        await guest.send("room.signal", data={"kind": "request"})
        r = await host.wait("room.signal")
        check("signal relayed", r.get("data", {}).get("kind") == "request")

        await guest.send("chat.send", text="hello there")
        r = await host.wait("chat")
        check("chat relayed", r.get("text") == "hello there" and r.get("from") == "Guest_1")

        await guest.call("room.leave")
        r = await host.wait("room.peer")
        check("leave notifies host", r.get("event") == "left")

        # wrong room
        r = await guest.call("room.join", code="ZZZZZ")
        check("bad room code rejected", r.get("code") == "NO_ROOM")

        # recovery + password change
        await c.ws.close()
        await c3.ws.close()
        await c4.ws.close()
        c5 = await conn()
        r = await c5.call("recover", username="Alice_1", code=recovery, newPassword="newpassword123")
        check("recovery works", r.get("op") == "ok" and isinstance(r.get("recovery"), list))
        r = await c5.call("login", username="Alice_1", password="newpassword123")
        check("login with recovered password", r.get("op") == "session")
        r = await c5.call("password.change", old="newpassword123", new="anotherpass123")
        check("password change", r.get("op") == "ok" and r.get("token"))
        r = await c5.call("login", username="Alice_1", password="anotherpass123")
        check("login with changed password", r.get("op") == "session")

        # rate limit (register attempts from same ip)
        rl = await conn()
        got = None
        for _ in range(14):
            r = await rl.call("register", username="Rl_%d" % _, password="password12345")
            if r.get("code") == "RATE_LIMIT":
                got = r
                break
        check("auth rate limiting kicks in", got is not None, "after %d tries" % _)

        await c.ws.close()
        await c2.ws.close()
        await c3.ws.close()
        await c4.ws.close()
        await c5.ws.close()
        await anon.ws.close()
        await host.ws.close()
        await guest.ws.close()
        await rl.ws.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
