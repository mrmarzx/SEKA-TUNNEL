#!/usr/bin/env python3
# SEKA TUNEL - New UI backend (real data from /etc/seka-tunel)
# Serves static UI + JSON API

import json, os, time, hashlib, secrets, subprocess
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

CONF = Path("/etc/seka-tunel")
TUN = CONF / "tunnels.conf"
RULES = CONF / "rules.conf"
GAAF_DIR = CONF / "gaaf"
BAL_DIR = CONF / "balancer"
NODES = BAL_DIR / "nodes.conf"
POOLS = BAL_DIR / "pools.conf"
WEB_ROOT = Path(os.environ.get("SEKA_WEB_ROOT", Path(__file__).resolve().parent))
PORT = int(os.environ.get("SEKA_UI_PORT", "8450"))
TOKEN_FILE = CONF / "ui_token"
SESSIONS = {}

def ensure_dirs():
    for d in (CONF, GAAF_DIR, BAL_DIR, GAAF_DIR / "keys", GAAF_DIR / "certs"):
        d.mkdir(parents=True, exist_ok=True)
    if not NODES.exists():
        NODES.write_text("")
    if not POOLS.exists():
        POOLS.write_text("")
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(secrets.token_hex(16))
        TOKEN_FILE.chmod(0o600)

def read_token():
    ensure_dirs()
    return TOKEN_FILE.read_text().strip()

def parse_pipe(path, min_fields=1):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) >= min_fields:
            rows.append(parts)
    return rows

def tunnels():
    out = []
    for p in parse_pipe(TUN, 2):
        # id|foreign_ip|udp_port|mtu|...|active|preset|type|...|name|...|transport
        item = {
            "id": p[0],
            "ip": p[1] if len(p) > 1 else "",
            "port": p[2] if len(p) > 2 else "",
            "active": (p[8] if len(p) > 8 else "0") in ("1", "true", "yes"),
            "preset": p[9] if len(p) > 9 else "",
            "type": p[10] if len(p) > 10 else "fwd",
            "name": p[12] if len(p) > 12 else f"tunnel{p[0]}",
            "tr": p[14] if len(p) > 14 else "udp",
            "pending": (p[1] if len(p) > 1 else "") == "pending",
        }
        out.append(item)
    return out

def gaaf_tunnels():
    out = []
    if not GAAF_DIR.exists():
        return out
    for meta in GAAF_DIR.glob("*.meta"):
        d = {}
        for line in meta.read_text(errors="ignore").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
        if d:
            out.append(d)
    return out

def nodes():
    out = []
    for p in parse_pipe(NODES, 3):
        out.append({
            "id": p[0], "name": p[1], "host": p[2],
            "port": p[3] if len(p) > 3 else "24444",
            "weight": p[4] if len(p) > 4 else "100",
            "status": p[5] if len(p) > 5 else "up",
        })
    return out

def pools():
    out = []
    for p in parse_pipe(POOLS, 3):
        out.append({
            "id": p[0], "name": p[1], "strategy": p[2],
            "nodes": p[3] if len(p) > 3 else "",
        })
    return out

def stats():
    ts = tunnels()
    gs = gaaf_tunnels()
    ns = nodes()
    return {
        "tunnels": len(ts),
        "gaaf": len(gs),
        "nodes": len(ns),
        "running_gaaf": sum(1 for g in gs if g.get("status") == "running"),
        "time": int(time.time()),
    }

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(WEB_ROOT), **kw)

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Token")
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        # Optional lightweight token; if UI token header missing, still allow local read
        tok = self.headers.get("X-Token") or self.headers.get("Authorization", "").replace("Bearer ", "")
        if not tok:
            return True  # open local panel mode
        return tok == read_token()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Token")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path.startswith("/api/"):
            if not self._auth_ok():
                return self._json(401, {"ok": False, "error": "unauthorized"})
            if path == "/api/stats":
                return self._json(200, {"ok": True, "data": stats()})
            if path == "/api/tunnels":
                return self._json(200, {"ok": True, "data": tunnels()})
            if path == "/api/gaaf":
                return self._json(200, {"ok": True, "data": gaaf_tunnels()})
            if path == "/api/nodes":
                return self._json(200, {"ok": True, "data": nodes()})
            if path == "/api/pools":
                return self._json(200, {"ok": True, "data": pools()})
            if path == "/api/token":
                return self._json(200, {"ok": True, "token": read_token()})
            return self._json(404, {"ok": False, "error": "not found"})
        # static
        if path == "/" or path == "":
            self.path = "/index.html"
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode() or "{}")
        except Exception:
            data = {}
        if not self._auth_ok():
            return self._json(401, {"ok": False, "error": "unauthorized"})

        if path == "/api/nodes/add":
            ensure_dirs()
            nid = str(data.get("id") or secrets.token_hex(2))
            name = str(data.get("name") or f"node-{nid}")
            host = str(data.get("host") or "")
            port = str(data.get("port") or "24444")
            weight = str(data.get("weight") or "100")
            if not host:
                return self._json(400, {"ok": False, "error": "host required"})
            with NODES.open("a") as f:
                f.write(f"{nid}|{name}|{host}|{port}|{weight}|up|\n")
            return self._json(200, {"ok": True, "id": nid})

        if path == "/api/gaaf/create":
            ensure_dirs()
            tid = str(data.get("id") or secrets.randbelow(900)+100)
            direction = str(data.get("direction") or "rev")
            profile = str(data.get("profile") or "balanced")
            # call shell module if available
            script = "/usr/local/lib/seka-tunel/gaaf.sh"
            if Path(script).exists():
                cmd = f"source {script}; gaaf_on_tunnel_create '{tid}' '{direction}' '24444' 'gaaf-{tid}' '' '' '{profile}'"
                subprocess.run(["bash", "-lc", cmd], check=False)
            else:
                meta = GAAF_DIR / f"{tid}.meta"
                meta.write_text(
                    f"id={tid}\nname=gaaf-{tid}\ndirection={direction}\nport=24444\nprofile={profile}\nstatus=prepared\nversion=1.3.0\n"
                )
            return self._json(200, {"ok": True, "id": tid})

        if path == "/api/pools/add":
            ensure_dirs()
            pid = str(data.get("id") or secrets.token_hex(2))
            name = str(data.get("name") or f"pool-{pid}")
            strategy = str(data.get("strategy") or "weighted")
            nids = str(data.get("nodes") or "")
            with POOLS.open("a") as f:
                f.write(f"{pid}|{name}|{strategy}|{nids}\n")
            return self._json(200, {"ok": True, "id": pid})


        if path == "/api/tunnels/add":
            # Classic port-forward entry: name|proto|listen|dest_ip|dest_port
            ensure_dirs()
            name = str(data.get("name") or "fwd")
            proto = str(data.get("proto") or "tcp")
            listen = str(data.get("listen") or data.get("port") or "")
            dest_ip = str(data.get("dest_ip") or data.get("ip") or "")
            dest_port = str(data.get("dest_port") or listen)
            if not listen or not dest_ip:
                return self._json(400, {"ok": False, "error": "listen and dest_ip required"})
            RULES.parent.mkdir(parents=True, exist_ok=True)
            with RULES.open("a") as f:
                f.write(f"{name}|{proto}|{listen}|{dest_ip}|{dest_port}\n")
            # try apply via CLI if available
            try:
                subprocess.run(["seka-tunel", "apply"], check=False, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            return self._json(200, {"ok": True, "name": name, "listen": listen})

        if path == "/api/tunnels/delete":
            ensure_dirs()
            key = str(data.get("id") or data.get("listen") or data.get("name") or "")
            if not key:
                return self._json(400, {"ok": False, "error": "id/listen/name required"})
            # delete from rules.conf by listen port or name
            if RULES.exists():
                lines = []
                for line in RULES.read_text(errors="ignore").splitlines():
                    parts = line.split("|")
                    if not parts:
                        continue
                    if parts[0] == key or (len(parts) > 2 and parts[2] == key):
                        continue
                    lines.append(line)
                RULES.write_text("\n".join(lines) + ("\n" if lines else ""))
            # delete tunnel row by id
            if TUN.exists():
                lines = []
                for line in TUN.read_text(errors="ignore").splitlines():
                    if line.startswith(key + "|"):
                        continue
                    lines.append(line)
                TUN.write_text("\n".join(lines) + ("\n" if lines else ""))
            try:
                subprocess.run(["seka-tunel", "apply"], check=False, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            return self._json(200, {"ok": True})

        if path == "/api/check/run":
            # trigger checker summary
            script = "/usr/local/lib/seka-tunel/checker.sh"
            if Path(script).exists():
                r = subprocess.run(
                    ["bash", "-lc", f"source {script}; chk_all_tunnels"],
                    capture_output=True, text=True, timeout=120
                )
                return self._json(200, {"ok": True, "output": r.stdout[-8000:]})
            return self._json(200, {"ok": True, "output": "checker module not installed"})

        return self._json(404, {"ok": False, "error": "not found"})

def main():

    ensure_dirs()
    print(f"SEKA UI backend on http://0.0.0.0:{PORT}")
    print(f"Web root: {WEB_ROOT}")
    print(f"UI token: {read_token()}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()
