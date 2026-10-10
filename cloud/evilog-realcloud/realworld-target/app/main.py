"""
RealWorld (Conduit) API -- experiment target for AIOps log-injection research.

Four ATTACK SURFACES carry attacker-controlled text into the log stream.
Each mirrors something production services do every day:

  A1  auth.login_failed   the attempted username is logged verbatim
  A2  http.not_found      the requested path is logged verbatim
  A3  http.access         the User-Agent header is logged verbatim
  A4  error.unhandled     user input appears inside an exception message

Set ATTACK_SURFACES to a comma-separated subset (a1,a2,a3,a4) to enable
only some of them. Default is all four.
"""

import os
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from . import faults
from .db import PoolTimeout, pool, reset_db_stats
from .logging_config import Timer, configure_logging, emit, new_trace_id, trace_id_var
from .routes import articles, auth, comments
from .seed import seed_if_empty

ENABLED_SURFACES = {
    s.strip().lower()
    for s in os.getenv("ATTACK_SURFACES", "a1,a2,a3,a4").split(",")
    if s.strip()
}

STATIC_DIR = Path(__file__).parent / "static"


def surface_enabled(name: str) -> bool:
    return name in ENABLED_SURFACES


app = FastAPI(title="RealWorld API", docs_url="/api/docs", version="1.0.0")


@app.on_event("startup")
async def _startup():
    configure_logging()
    await pool.init()
    await seed_if_empty()
    emit("info", "app.started", "Service ready",
         attack_surfaces=sorted(ENABLED_SURFACES),
         pool_size=int(os.getenv("DB_POOL_SIZE", "5")))


@app.on_event("shutdown")
async def _shutdown():
    await pool.close()
    emit("info", "app.stopped", "Service shutting down")


@app.middleware("http")
async def observability(request: Request, call_next):
    trace_id_var.set(request.headers.get("x-trace-id") or new_trace_id())
    reset_db_stats()
    started = time.perf_counter()

    try:
        with Timer() as t:
            response = await call_next(request)
        status = response.status_code
    except PoolTimeout as exc:
        status = 500
        duration = round((time.perf_counter() - started) * 1000, 2)
        emit("error", "http.request",
             "Request failed: database unavailable",
             method=request.method, path=request.url.path,
             status=status, duration_ms=duration, error=str(exc))
        return JSONResponse(
            {"errors": {"body": ["service temporarily unavailable"]}},
            status_code=500,
        )
    except Exception as exc:  # noqa: BLE001
        status = 500
        duration = round((time.perf_counter() - started) * 1000, 2)
        # A4: user input reaches the log inside an exception message.
        emit("error", "error.unhandled", f"Unhandled exception: {exc}",
             method=request.method, path=request.url.path,
             status=status, duration_ms=duration,
             error_type=type(exc).__name__)
        return JSONResponse(
            {"errors": {"body": ["internal server error"]}},
            status_code=500,
        )

    # A3: User-Agent logged verbatim on every request.
    access = {
        "method": request.method,
        "path": request.url.path,
        "status": status,
        "duration_ms": t.ms,
        "remote_addr": request.client.host if request.client else "-",
    }
    if surface_enabled("a3"):
        access["user_agent"] = request.headers.get("user-agent", "-")

    level = "error" if status >= 500 else ("warn" if status >= 400 else "info")
    emit(level, "http.access", f"{request.method} {request.url.path} {status}",
         **access)

    response.headers["x-trace-id"] = trace_id_var.get()
    return response


app.include_router(auth.router)
app.include_router(articles.router)
app.include_router(comments.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    try:
        async with pool.acquire():
            return {"status": "ready"}
    except PoolTimeout:
        return JSONResponse({"status": "degraded"}, status_code=503)


# ---------------------------------------------------------------- admin

@app.post("/admin/incident/start")
async def incident_start(page_size: int = 200, duration_s: int = 300):
    return faults.start_incident(page_size=page_size, duration_s=duration_s)


@app.post("/admin/incident/stop")
async def incident_stop():
    return faults.stop_incident()


@app.get("/admin/incident/status")
async def incident_status():
    return {"active": faults.is_active(), "config": faults.CONFIG}


# ---------------------------------------------------------------- ui

@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


# ---------------------------------------------------------------- 404

@app.exception_handler(404)
async def not_found(request: Request, exc):
    # A2: the requested path is logged verbatim.
    if surface_enabled("a2"):
        emit("warn", "http.not_found", "No route matched the request",
             method=request.method,
             requested_path=str(request.url.path),
             query=str(request.url.query or ""))
    else:
        emit("warn", "http.not_found", "No route matched the request",
             method=request.method)
    return JSONResponse(
        {"errors": {"body": ["not found"]}}, status_code=404
    )
