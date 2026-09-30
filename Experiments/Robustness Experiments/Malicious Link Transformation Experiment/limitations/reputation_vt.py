#!/usr/bin/env python3
"""
Limitations analysis: adding URL reputation (VirusTotal) on top of Evilog + static resolver.

Only the 3 external links (L23-L25) and the benign controls are queried:
sending internal URLs to a third-party service is itself a leak.

Requires OPENAI_API_KEY; VT_API_KEY optional (free tier: 4 requests/min).
Expected: domains that VirusTotal has never seen (e.g. freshly registered phishing
domains) are still missed, which is why reputation alone does not close the gap.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from links import LINKS, BENIGN_CONTROLS
from static_resolver import is_ssrf
from detector import classify, leaves_memo

VT_KEY = os.getenv("VT_API_KEY")


def vt_malicious(url):
    """True if VirusTotal reports the domain as malicious; False if clean/unknown; None if unavailable."""
    if not VT_KEY:
        return None
    host = urlsplit(url).hostname
    try:
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/domains/{host}",
                                     headers={"x-apikey": VT_KEY})
        with urllib.request.urlopen(req, timeout=20) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) > 0
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def main():
    targets = [r for r in LINKS if r[1] == "external"] + BENIGN_CONTROLS
    print(f"VirusTotal: {'ON' if VT_KEY else 'OFF (set VT_API_KEY)'}\n")
    print(f"{'id':4} {'label':26} {'Evilog':7} {'+static':8} {'+reputation'}")
    print("-" * 64)
    for lid, _, label, url in targets:
        llm = leaves_memo(classify(url))
        st = llm or is_ssrf(url)
        rep = vt_malicious(url)
        rep_col = "N/A" if rep is None else ("memo" if (st or rep) else "none")
        print(f"{lid:4} {label:26} {'memo' if llm else 'none':7} {'memo' if st else 'none':8} {rep_col}")
        if VT_KEY:
            time.sleep(16)


if __name__ == "__main__":
    main()
