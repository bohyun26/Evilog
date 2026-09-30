#!/usr/bin/env python3
"""
Malicious-link transformation experiment (paper: 25 link variants).

For each of the 25 links:
  Evilog            : the LLM security detector leaves a memo if its verdict names an attack
  Evilog + static   : memo if the static URL resolver flags it OR the LLM detector does

Outputs a per-link table and saves results/ssrf_eval_<timestamp>.json and .csv.

Usage
  python run_ssrf_eval.py                 # needs OPENAI_API_KEY
  python run_ssrf_eval.py --repeat 5      # repeat the LLM verdict 5x per link (majority vote)
  python run_ssrf_eval.py --controls      # also run 3 benign links (false-positive check)
  python run_ssrf_eval.py --static-only   # no API calls; static resolver column only
"""
import argparse
import csv
import json
import os
import time
from collections import Counter

from links import LINKS, BENIGN_CONTROLS
from static_resolver import explain

HERE = os.path.dirname(os.path.abspath(__file__))


def llm_verdict(url, repeat):
    from detector import classify, leaves_memo
    verdicts = [classify(url) for _ in range(repeat)]
    memos = [leaves_memo(v) for v in verdicts]
    majority = Counter(memos).most_common(1)[0][0]
    return verdicts, sum(memos), majority


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--controls", action="store_true")
    ap.add_argument("--static-only", action="store_true")
    args = ap.parse_args()

    rows_in = [(*r, True) for r in LINKS]
    if args.controls:
        rows_in += [(*r, False) for r in BENIGN_CONTROLS]

    if not args.static_only:
        from detector import DET_MODEL, DET_PROMPT
        print(f"LLM detector: {DET_MODEL} (prompt {DET_PROMPT}), repeat={args.repeat}")
    print(f"{'id':4} {'group':18} {'label':26} {'Evilog':8} {'+static':8} static reason")
    print("-" * 100)

    rows = []
    for lid, group, label, url, is_attack in rows_in:
        s_block, s_reason = explain(url)
        if args.static_only:
            verdicts, n_memo, llm = [], None, None
            combined = s_block
        else:
            verdicts, n_memo, llm = llm_verdict(url, args.repeat)
            combined = llm or s_block
        rows.append({"id": lid, "group": group, "label": label, "url": url, "is_attack": is_attack,
                     "llm_verdicts": verdicts, "llm_memo_count": n_memo, "llm_memo": llm,
                     "static_block": s_block, "static_reason": s_reason, "evilog_plus_static": combined})
        c1 = "-" if llm is None else ("memo" if llm else "none")
        c2 = "memo" if combined else "none"
        print(f"{lid:4} {group:18} {label:26} {c1:8} {c2:8} {s_reason}")

    attacks = [r for r in rows if r["is_attack"]]
    n = len(attacks)
    print("-" * 100)
    if not args.static_only:
        k1 = sum(r["llm_memo"] for r in attacks)
        print(f"Evilog (LLM only)      : {k1}/{n} = {k1 / n:.0%}")
    k2 = sum(r["evilog_plus_static"] for r in attacks)
    print(f"Evilog + static        : {k2}/{n} = {k2 / n:.0%}")
    missed = [r["label"] for r in attacks if not r["evilog_plus_static"]]
    print(f"Missed with static     : {missed}")
    if args.controls:
        fp = [r["label"] for r in rows if not r["is_attack"] and r["evilog_plus_static"]]
        print(f"False positives (benign): {len(fp)}/{len(BENIGN_CONTROLS)} {fp}")

    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(HERE, "results", f"ssrf_eval_{stamp}")
    meta = {"det_model": None if args.static_only else os.environ.get("DET_MODEL", "gpt-4o-mini"),
            "det_prompt": None if args.static_only else os.environ.get("DET_PROMPT", "v2"),
            "repeat": args.repeat, "static_only": args.static_only, "timestamp": stamp}
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "rows": rows}, f, ensure_ascii=False, indent=2)
    with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "group", "label", "url", "is_attack", "llm_memo", "static_block", "evilog_plus_static"])
        for r in rows:
            w.writerow([r["id"], r["group"], r["label"], r["url"], r["is_attack"],
                        r["llm_memo"], r["static_block"], r["evilog_plus_static"]])
    print(f"\nsaved: {base}.json / .csv")


if __name__ == "__main__":
    main()
