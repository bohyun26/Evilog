"""
Drive traffic and inject payloads through the four attack surfaces.

Usage:
    py -3.12 attack\\send_attacks.py --base-url http://<ELB-DNS> --incident
    py -3.12 attack\\send_attacks.py --base-url http://localhost:8080 --surface a1
"""

import argparse
import asyncio
import json
import random
import time
import urllib.parse
from pathlib import Path

import httpx

PAYLOADS = json.loads(
    (Path(__file__).parent / "payloads.json").read_text(encoding="utf-8")
)["payloads"]


async def surface_a1(c, text):
    """Login failure -> attempted_username."""
    r = await c.post("/api/users/login",
                     json={"user": {"username": text, "password": "wrong"}})
    return "a1", r.status_code


async def surface_a2(c, text):
    """404 -> requested_path."""
    r = await c.get("/api/" + urllib.parse.quote(text, safe=""))
    return "a2", r.status_code


async def surface_a3(c, text):
    """Access log -> user_agent."""
    r = await c.get("/api/articles", headers={"user-agent": text})
    return "a3", r.status_code


async def surface_a4(c, text):
    """Comment body -> body_preview."""
    r = await c.post("/api/articles/post-0001/comments",
                     json={"comment": {"body": text}})
    return "a4", r.status_code


SURFACES = {"a1": surface_a1, "a2": surface_a2,
            "a3": surface_a3, "a4": surface_a4}


async def background_traffic(c, stop_at, rps=6):
    """Ordinary user traffic so the incident has a realistic backdrop."""
    while time.time() < stop_at:
        await asyncio.gather(
            *[c.get("/api/articles") for _ in range(rps)],
            return_exceptions=True,
        )
        await asyncio.sleep(1.0)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--surface", default="all", help="a1|a2|a3|a4|all")
    ap.add_argument("--payload", default="all", help="payload id or 'all'")
    ap.add_argument("--incident", action="store_true",
                    help="trigger the pool-exhaustion incident first")
    ap.add_argument("--duration", type=int, default=60,
                    help="seconds of background traffic")
    args = ap.parse_args()

    chosen = (list(SURFACES) if args.surface == "all"
              else [s.strip() for s in args.surface.split(",")])
    payloads = (PAYLOADS if args.payload == "all"
                else [p for p in PAYLOADS if p["id"] == args.payload])

    async with httpx.AsyncClient(base_url=args.base_url, timeout=30) as c:
        if args.incident:
            r = await c.post("/admin/incident/start",
                             params={"page_size": 200,
                                     "duration_s": args.duration + 30})
            print("incident started:", r.json())

        stop_at = time.time() + args.duration
        bg = asyncio.create_task(background_traffic(c, stop_at))

        sent = []
        for p in payloads:
            for name in chosen:
                try:
                    surface, status = await SURFACES[name](c, p["text"])
                    sent.append({"payload": p["id"], "surface": surface,
                                 "status": status,
                                 "sent_at": time.time()})
                    print(f"  sent {p['id']:22s} via {surface}  -> {status}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  FAIL {p['id']:22s} via {name}: {exc}")
                await asyncio.sleep(random.uniform(0.3, 0.9))

        await bg
        if args.incident:
            r = await c.post("/admin/incident/stop")
            print("incident stopped:", r.json())

    out = Path(__file__).parent / "sent_payloads.json"
    out.write_text(json.dumps(sent, indent=2), encoding="utf-8")
    print(f"\n{len(sent)} injections recorded -> {out}")


if __name__ == "__main__":
    asyncio.run(main())
