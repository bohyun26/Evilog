"""Seed data so the feed has enough rows for the N+1 to bite."""

import time

from .db import execute, pool, query
from .logging_config import emit
from .routes.auth import hash_password

AUTHORS = ["ada", "linus", "grace", "ken", "barbara", "alan"]
TOPICS = [
    "How to build a Conduit clone", "Structured logging in production",
    "Connection pools and you", "Why N+1 queries hide so well",
    "Reading a p99 latency chart", "Postmortems worth writing",
    "Cache invalidation, revisited", "On-call without the dread",
]


async def seed_if_empty(article_count: int = 4000) -> None:
    async with pool.acquire() as conn:
        existing = await query(conn, "SELECT COUNT(*) AS n FROM users", tag="seed_check")
        if existing[0]["n"] > 0:
            emit("info", "db.seed.skipped", "Seed data already present")
            return

        for name in AUTHORS:
            await execute(
                conn,
                "INSERT INTO users (username, email, password_hash, bio, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (name, f"{name}@example.com", hash_password("password"),
                 f"{name} writes about systems.", time.time()),
            )

        now = time.time()
        for i in range(article_count):
            topic = TOPICS[i % len(TOPICS)]
            await execute(
                conn,
                "INSERT INTO articles (slug, title, description, body, author_id,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (f"post-{i:04d}", f"{topic} (part {i // len(TOPICS) + 1})",
                 "A short note from the seed corpus.",
                 "Body text for the seeded article.",
                 (i % len(AUTHORS)) + 1, now - i * 60),
            )

    emit("info", "db.seed.complete", "Seed data loaded",
         users=len(AUTHORS), articles=article_count)
