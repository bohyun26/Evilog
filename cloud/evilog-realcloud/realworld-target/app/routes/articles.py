"""
Article routes.

`GET /api/articles` contains the N+1 that turns the config change into
an outage. It is a real N+1, not a sleep: one author lookup per article
returned. `feed_page_size` controls how many articles come back, so
raising it multiplies the query count and the time the pooled connection
is held.
"""

import time

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .. import faults
from ..db import execute, pool, query, request_db_stats
from ..logging_config import emit

router = APIRouter(prefix="/api/articles", tags=["articles"])


def slugify(title: str) -> str:
    base = "".join(c.lower() if c.isalnum() else "-" for c in title)
    return "-".join(filter(None, base.split("-")))[:80] or "untitled"


class ArticleIn(BaseModel):
    title: str
    description: str = ""
    body: str = ""


class ArticlePayload(BaseModel):
    article: ArticleIn


@router.get("")
async def list_articles(limit: int | None = Query(default=None)):
    page_size = limit or faults.CONFIG["feed_page_size"]

    async with pool.acquire() as conn:
        rows = await query(
            conn,
            "SELECT id, slug, title, description, author_id, created_at"
            " FROM articles ORDER BY created_at DESC LIMIT ?",
            (page_size,),
            tag="articles_page",
        )

        # --- the N+1 -------------------------------------------------
        # One lookup per article. Cheap at page_size=10, ruinous at 200,
        # and the pooled connection is held for the whole loop.
        out = []
        for row in rows:
            # The author card shows a post count. There is no index on
            # articles.author_id, so this correlated COUNT is a genuine
            # full scan of the articles table -- once per article in the
            # page. That is the real cost that holds the connection.
            author = await query(
                conn,
                "SELECT u.username, u.bio,"
                " (SELECT COUNT(*) FROM articles a WHERE a.author_id = u.id)"
                " AS post_count"
                " FROM users u WHERE u.id = ?",
                (row["author_id"],),
                tag="author_by_id",
            )
            out.append({
                "slug": row["slug"],
                "title": row["title"],
                "description": row["description"],
                "createdAt": row["created_at"],
                "author": {
                    "username": author[0]["username"] if author else "unknown",
                    "bio": author[0]["bio"] if author else "",
                },
            })
        # -------------------------------------------------------------

    stats = request_db_stats()
    if stats["total_ms"] >= 100:
        emit("warn", "db.request.slow",
             "Database time dominates the request",
             total_query_ms=stats["total_ms"], query_count=stats["count"],
             endpoint="/api/articles")

    if page_size > 50:
        emit("warn", "feed.oversized_page",
             "Feed page size exceeds the recommended maximum",
             page_size=page_size, recommended_max=50,
             queries_issued=len(rows) + 1)

    return {"articles": out, "articlesCount": len(out)}


@router.get("/{slug}")
async def get_article(slug: str):
    async with pool.acquire() as conn:
        rows = await query(
            conn,
            "SELECT a.slug, a.title, a.description, a.body, a.created_at,"
            " u.username FROM articles a JOIN users u ON u.id = a.author_id"
            " WHERE a.slug = ?",
            (slug,),
            tag="article_by_slug",
        )
    if not rows:
        emit("warn", "article.not_found", "Article lookup missed",
             slug=slug)
        return JSONResponse(
            {"errors": {"body": ["article not found"]}}, status_code=404
        )
    row = rows[0]
    return {"article": {
        "slug": row["slug"], "title": row["title"],
        "description": row["description"], "body": row["body"],
        "createdAt": row["created_at"],
        "author": {"username": row["username"]},
    }}


@router.post("", status_code=201)
async def create_article(payload: ArticlePayload):
    art = payload.article
    slug = f"{slugify(art.title)}-{int(time.time() * 1000) % 100000}"
    async with pool.acquire() as conn:
        article_id = await execute(
            conn,
            "INSERT INTO articles (slug, title, description, body, author_id,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (slug, art.title, art.description, art.body, 1, time.time()),
        )
    emit("info", "article.created", "Article published",
         article_id=article_id, slug=slug, title=art.title)
    return {"article": {"slug": slug, "title": art.title,
                        "description": art.description, "body": art.body}}
