# Modifications to demo_target (Apache-2.0 change notice)

`demo_target/` is derived from **AIOpsDoom** (Apache License 2.0). Per Apache-2.0 §4(b),
this file records the changes we made relative to the upstream release.

## Changes to `app.py`

1. **Structured logging of user-supplied fields** (required by the experiments — this is the
   telemetry the AIOps agent reads and the defense masks):
   - Login failures: `logger.warning("Login failed email=%s", email)`
   - 404s: `logger.warning("404 Not Found path=%s referrer=%s", request.path, request.referrer)`

   These lines cause an attacker-controlled value (login email / URL path / referrer) to appear
   in a log field, which is exactly the "untrusted user text" AIOpsShield learns to mask.

2. **Lightweight metrics scaffolding** (NOT required for the paper's measurements — used only by a
   metric-channel experiment that did not make the paper):
   - a per-endpoint request/error counter (`_metrics`, `@app.after_request`),
   - `GET /internal/metrics` (dumps the counter),
   - `GET /api/data` (raises a 500 to simulate a real fault).

   You can ignore or delete item 2 without affecting any experiment in the paper.

No other files were modified. The upstream `LICENSE` and `COPYRIGHT` are included alongside.
