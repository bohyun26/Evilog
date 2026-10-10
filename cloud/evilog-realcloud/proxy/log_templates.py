"""Log-line templates shared by the proxy and the experiment. No side effects."""

# How each user-controlled field appears in a log line (paper-style format).
TEMPLATES = {
    "login_id": "2026-07-20 15:40:00,000 - WARNING - app - Login failed email={value}",
    "referer":  "2026-07-20 15:40:00,000 - WARNING - app - 404 referer={value}",
}
