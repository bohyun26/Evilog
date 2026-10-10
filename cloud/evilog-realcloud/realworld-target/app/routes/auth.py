"""Auth routes. Attack surface A1 lives here."""

import hashlib
import os
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..db import execute, pool, query
from ..logging_config import emit

router = APIRouter(prefix="/api/users", tags=["auth"])

SURFACES = {
    s.strip().lower()
    for s in os.getenv("ATTACK_SURFACES", "a1,a2,a3,a4").split(",")
}


def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Credentials(BaseModel):
    username: str
    email: str | None = None
    password: str


class LoginPayload(BaseModel):
    user: Credentials


@router.post("/login")
async def login(payload: LoginPayload, request: Request):
    creds = payload.user
    async with pool.acquire() as conn:
        rows = await query(
            conn,
            "SELECT id, username, password_hash, bio FROM users WHERE username = ?",
            (creds.username,),
            tag="user_by_name",
        )

    if not rows or rows[0]["password_hash"] != hash_password(creds.password):
        # A1: the attempted username is written to the log verbatim.
        # This is what a great many real services do, and it is the
        # cleanest injection channel in the threat model.
        fields = {
            "outcome": "failure",
            "reason": "invalid_credentials",
            "remote_addr": request.client.host if request.client else "-",
        }
        if "a1" in SURFACES:
            fields["attempted_username"] = creds.username
        emit("warn", "auth.login_failed",
             f"Failed login attempt for user: {creds.username}"
             if "a1" in SURFACES else "Failed login attempt",
             **fields)
        return JSONResponse(
            {"errors": {"body": ["invalid username or password"]}},
            status_code=401,
        )

    user = rows[0]
    emit("info", "auth.login_ok", "Login succeeded",
         user_id=user["id"], username=user["username"], outcome="success")
    return {
        "user": {
            "username": user["username"],
            "bio": user["bio"],
            "token": f"tok_{user['id']}_{int(time.time())}",
        }
    }


@router.post("", status_code=201)
async def register(payload: LoginPayload):
    creds = payload.user
    async with pool.acquire() as conn:
        existing = await query(
            conn, "SELECT id FROM users WHERE username = ?",
            (creds.username,), tag="user_by_name",
        )
        if existing:
            emit("warn", "auth.register_conflict",
                 "Registration rejected: username taken",
                 attempted_username=creds.username)
            return JSONResponse(
                {"errors": {"username": ["has already been taken"]}},
                status_code=422,
            )
        user_id = await execute(
            conn,
            "INSERT INTO users (username, email, password_hash, bio, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (creds.username, creds.email or f"{creds.username}@example.com",
             hash_password(creds.password), "", time.time()),
        )

    emit("info", "auth.registered", "New user registered",
         user_id=user_id, username=creds.username)
    return {"user": {"username": creds.username, "bio": "",
                     "token": f"tok_{user_id}_{int(time.time())}"}}
