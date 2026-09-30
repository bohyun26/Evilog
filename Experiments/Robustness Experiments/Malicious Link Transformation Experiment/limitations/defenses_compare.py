#!/usr/bin/env python3
"""
Limitations analysis: static URL-defense alternatives on the same 25 links (no API key, no fetching).

  BL  blacklist regex on the raw string          (misses encoded IPs)
  NR  normalization + dangerous IP ranges         (decode host, block internal ranges)
  SR  static resolver = NR + dangerous schemes    (the static detector used in Evilog)
  WL  allowlist / default-deny                    (catches everything, but blocks legitimate URLs too)

Redirection analysis is not included: following redirects needs a real fetch,
which introduces its own security risks (see paper, Limitations).
"""
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from links import LINKS, BENIGN_CONTROLS
from static_resolver import host_to_ip, is_internal, is_ssrf

BLACKLIST = [r"169\.254\.169\.254", r"127\.0\.0\.1", r"\blocalhost\b", r"10\.\d+\.\d+\.\d+",
             r"192\.168\.", r"172\.(1[6-9]|2\d|3[01])\.", r"::1"]
ALLOWLIST = {"api.stripe.com", "github.com", "www.google.com"}

DEFENSES = [
    ("BL", lambda u: any(re.search(p, u) for p in BLACKLIST)),
    ("NR", lambda u: is_internal(host_to_ip(urlsplit(u).hostname))),
    ("SR", is_ssrf),
    ("WL", lambda u: (urlsplit(u).hostname or "") not in ALLOWLIST),
]


def main():
    names = [n for n, _ in DEFENSES]
    print("(X = blocked, . = passed)\n")
    print(f"{'id':4} {'label':26} " + "  ".join(f"{n:>2}" for n in names))
    print("-" * 50)
    counts = {n: 0 for n in names}
    fps = {n: 0 for n in names}
    for lid, _, label, url in LINKS + BENIGN_CONTROLS:
        cells = []
        for n, fn in DEFENSES:
            b = fn(url)
            if lid.startswith("L"):
                counts[n] += b
            else:
                fps[n] += b
            cells.append(" X" if b else " .")
        print(f"{lid:4} {label:26} " + "  ".join(cells))
    print("-" * 50)
    print(f"{'blocked attacks (/25)':31}" + "  ".join(f"{counts[n]:>2}" for n in names))
    print(f"{'false positives (/3)':31}" + "  ".join(f"{fps[n]:>2}" for n in names))
    print("\nNote: WL blocks the 3 external links only because nothing outside the allowlist passes;"
          "\n      in production it also blocks every legitimate URL not on the list.")


if __name__ == "__main__":
    main()
