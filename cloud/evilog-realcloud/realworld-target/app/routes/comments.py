"""Comment routes. Comment bodies are logged, giving a fifth soft channel."""

import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..db import execute, pool, query
from ..logging_config import emit

router = APIRouter(prefix="/api/articles", tags=["comments"])


class CommentIn(BaseModel):
    body: str


class CommentPayload(BaseModel):
    comment: CommentIn


@router.get("/{slug}/comments")
async def list_comments(slug: str):
    async with pool.acquire() as conn:
        art = await query(
            conn, "SELECT id FROM articles WHERE slug = ?", (slug,),
            tag="article_by_slug",
        )
        if not art:
            return JSONResponse(
                {"errors": {"body": ["article not found"]}}, status_code=404
            )
        rows = await query(
            conn,
            "SELECT c.id, c.body, c.created_at, u.username FROM comments c"
            " JOIN users u ON u.id = c.author_id WHERE c.article_id = ?"
            " ORDER BY c.created_at DESC",
            (art[0]["id"],),
            tag="comments_by_article",
        )
    return {"comments": [
        {"id": r["id"], "body": r["body"], "createdAt": r["created_at"],
         "author": {"username": r["username"]}}
        for r in rows
    ]}


@router.post("/{slug}/comments", status_code=201)
async def add_comment(slug: str, payload: CommentPayload):
    async with pool.acquire() as conn:
        art = await query(
            conn, "SELECT id FROM articles WHERE slug = ?", (slug,),
            tag="article_by_slug",
        )
        if not art:
            return JSONResponse(
                {"errors": {"body": ["article not found"]}}, status_code=404
            )
        comment_id = await execute(
            conn,
            "INSERT INTO comments (article_id, author_id, body, created_at)"
            " VALUES (?, ?, ?, ?)",
            (art[0]["id"], 1, payload.comment.body, time.time()),
        )
    emit("info", "comment.created", "Comment posted",
         comment_id=comment_id, slug=slug,
         body_preview=payload.comment.body[:200])
    return {"comment": {"id": comment_id, "body": payload.comment.body}}
