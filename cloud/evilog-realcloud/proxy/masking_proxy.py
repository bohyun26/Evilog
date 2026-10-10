#!/usr/bin/env python3
"""
Masking proxy — position (a). Sits BETWEEN the app and the store the agent reads.

Flow (real cloud):
    Juice Shop pod --(log line + which field is user-controlled)--> THIS PROXY
        -> apply selected defense to that field (real AIOpsShield / Evilog)
        -> write ONLY the sanitized line to the store (CloudWatch)
    Raw log stays in the container for humans (AIOpsShield-style).

Endpoints:
    POST /ingest   {"template": "...{value}...", "field": "login_id", "value": "admin' OR..."}
                   -> masks `value`, fills template, appends to store. Returns sanitized line + memo.
    GET  /health

Run:
    DEFENSE=evilog STORE_BACKEND=cloudwatch RESEARCH_PATH=/path/to/harness \
      python proxy/masking_proxy.py
"""
import os, sys, json
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from proxy import config as cfg
from proxy.defenses import build_defenses
from agent.log_store import build_store
from proxy.log_templates import TEMPLATES

DEFENSE = os.environ.get("DEFENSE", "evilog")  # no_defense | aiopsshield | evilog
_defense = build_defenses(cfg)[DEFENSE]
_store = build_store(cfg)


def sanitize_line(template, field, value):
    masked, memo = _defense.sanitize(field, value)
    line = template.replace("{value}", masked)
    if memo:                       # Evilog: append the trusted evidence memo
        line = f"{line} {memo}"
    return line, memo


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "defense": DEFENSE, "store": cfg.STORE_BACKEND})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/ingest":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        line, memo = sanitize_line(req["template"], req.get("field", "login_id"), req["value"])
        _store.append(line)
        self._send(200, {"sanitized": line, "memo": memo})

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PROXY_PORT", "8092"))
    print(f"[proxy] defense={DEFENSE} store={cfg.STORE_BACKEND} :{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
