#!/usr/bin/env python3
"""Voidbreakers online power ranking server (stdlib only).

Run:
    python3 ranking_server.py
    python3 ranking_server.py --host 0.0.0.0 --port 8788 --data ranking.json

Endpoints:
    GET  /top?limit=20   -> {"ok":true,"entries":[{"name","power","updatedAt"}]}
    POST /submit         -> {"ok":true,"best":<best>,"rank":<rank>}
                            body: {"name":"Player","power":123456}
    GET  /health         -> {"ok":true,"entries":<n>}

Works from the game (file://) thanks to CORS. Share the URL on your LAN
(http://<your-ip>:8788) or host it on any small VPS / tunnel.
"""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA_PATH = "ranking.json"
DATA = {"entries": {}}
DATA_LOCK = threading.Lock()
RATE = {}
MAX_BODY = 4096
MAX_POWER = 1000000000000
TOP_LIMIT = 100


def load_data():
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            return data
    except Exception:
        pass
    return {"entries": {}}


def save_data(data):
    tmp = DATA_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_PATH)


def sanitize_name(raw):
    s = str(raw or "").strip()[:20]
    s = "".join(ch for ch in s if ch.isprintable() and ch not in "<>\n\r\t")
    return s if len(s) >= 2 else ""


class Handler(BaseHTTPRequestHandler):
    server_version = "VoidRank/1.0"

    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def out(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            with DATA_LOCK:
                n = len(DATA["entries"])
            return self.out(200, {"ok": True, "entries": n})
        if u.path == "/top":
            try:
                limit = int(parse_qs(u.query).get("limit", ["20"])[0])
            except Exception:
                limit = 20
            limit = max(1, min(TOP_LIMIT, limit))
            with DATA_LOCK:
                entries = sorted(DATA["entries"].values(), key=lambda e: (-e["power"], e["updatedAt"]))[:limit]
            return self.out(200, {"ok": True, "entries": [
                {"name": e["name"], "power": e["power"], "updatedAt": e["updatedAt"]} for e in entries
            ]})
        return self.out(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/submit":
            return self.out(404, {"ok": False, "error": "not found"})
        now = time.time()
        ip = self.client_address[0]
        with DATA_LOCK:
            win = RATE.get(ip)
            if win and now - win[0] < 10:
                win[1] += 1
                if win[1] > 20:
                    return self.out(429, {"ok": False, "error": "rate limited"})
            else:
                RATE[ip] = [now, 1]
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n <= 0 or n > MAX_BODY:
                return self.out(400, {"ok": False, "error": "bad body"})
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.out(400, {"ok": False, "error": "bad json"})
        name = sanitize_name(data.get("name"))
        if not name:
            return self.out(400, {"ok": False, "error": "bad name"})
        try:
            power = int(data.get("power"))
        except Exception:
            return self.out(400, {"ok": False, "error": "bad power"})
        if power < 0 or power > MAX_POWER:
            return self.out(400, {"ok": False, "error": "power out of range"})
        key = name.casefold()
        with DATA_LOCK:
            cur = DATA["entries"].get(key)
            best = max(power, cur["power"] if cur else 0)
            DATA["entries"][key] = {"name": name, "power": best, "updatedAt": int(now)}
            save_data(DATA)
            rank = 1 + sum(1 for e in DATA["entries"].values() if e["power"] > best)
        return self.out(200, {"ok": True, "best": best, "rank": rank})

    def log_message(self, *args):
        pass


def main():
    global DATA, DATA_PATH
    ap = argparse.ArgumentParser(description="Voidbreakers online power ranking server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--data", default="ranking.json")
    args = ap.parse_args()
    DATA_PATH = args.data
    DATA = load_data()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("Voidbreakers ranking server: http://%s:%d" % (args.host, args.port))
    print("Data: %s" % os.path.abspath(DATA_PATH))
    print("LAN: http://<your-ip>:%d  |  public: host this script on a VPS/tunnel" % args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
