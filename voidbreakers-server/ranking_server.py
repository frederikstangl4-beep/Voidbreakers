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
import html
import json
import os
import socket
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
PUBLIC_URL = ""


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


def lan_ips():
    ips = set()
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ips.add(probe.getsockname()[0])
        probe.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


def server_urls(port):
    lan = ["http://%s:%d" % (ip, port) for ip in lan_ips()]
    best = PUBLIC_URL or (lan[0] if lan else "")
    return lan, best


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
        if u.path == "/info":
            port = self.server.server_address[1]
            lan, best = server_urls(port)
            return self.out(200, {
                "ok": True, "port": port, "hostname": socket.gethostname(),
                "lan": lan, "public": PUBLIC_URL or None, "url": best,
            })
        if u.path in ("", "/", "/index.html"):
            with DATA_LOCK:
                entries = sorted(DATA["entries"].values(), key=lambda e: (-e["power"], e["updatedAt"]))[:20]
            port = self.server.server_address[1]
            lan, best = server_urls(port)
            rows = "".join(
                "<tr><td>%d</td><td>%s</td><td>%s</td></tr>" % (
                    i + 1, html.escape(e["name"]), format(e["power"], ","))
                for i, e in enumerate(entries)
            ) or "<tr><td colspan='3'>No scores yet.</td></tr>"
            share = []
            for u in ([best] if best else []) + lan:
                if u and u not in share:
                    share.append(u)
            links = "".join("<li>%s</li>" % html.escape(u) for u in share)
            page = (
                "<!doctype html><meta charset='utf-8'><title>Voidbreakers Power</title>"
                "<style>body{font-family:system-ui,sans-serif;background:#120a1c;color:#eee;padding:24px;}"
                "h1{font-size:20px;color:#e9b8ff}table{border-collapse:collapse;width:min(100%,560px);}"
                "td{padding:8px 10px;border-bottom:1px solid #332244}td:first-child{color:#9a7ab8;width:40px;}"
                "td:last-child{text-align:right;color:#ffd166}li{color:#8ad8ff;margin:4px 0}"
                "small{color:#9a8ab0}</style>"
                "<h1>Voidbreakers Power Rankings</h1>"
                "<p><small>Server URLs (use the LAN one on your phone):</small></p><ul>" + links + "</ul>"
                "<table>" + rows + "</table>"
                "<p><small>Enter one of these URLs in the game's Power panel.</small></p>"
            ).encode("utf-8")
            self.send_response(200)
            self.cors()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            try:
                self.wfile.write(page)
            except Exception:
                pass
            return
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
    ap.add_argument("--public-url", default="", help="optional public URL to advertise (tunnel/VPS)")
    args = ap.parse_args()
    DATA_PATH = args.data
    DATA = load_data()
    global PUBLIC_URL
    PUBLIC_URL = (args.public_url or "").strip().rstrip("/")
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    lan, best = server_urls(args.port)
    print("Voidbreakers ranking server: http://%s:%d" % (args.host, args.port))
    print("Data: %s" % os.path.abspath(DATA_PATH))
    if best:
        print("Share this URL: %s" % best)
    for u in lan:
        print("LAN URL: %s" % u)
    print("Phone says 'could not reach'? Same Wi-Fi + allow port %d in the firewall." % args.port)
    print("  Linux: sudo ufw allow %d/tcp    Windows/macOS: allow Python in the firewall." % args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
