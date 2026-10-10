#!/usr/bin/env python3
"""
experiment/curate.py - deterministic log selection for the real-cloud experiment.

WHY THIS EXISTS
---------------
The agent reads a bounded window (store.read_recent(n), n=50). The raw CloudWatch
window holds thousands of lines. Whether the causal chain OR the attack evidence
survived into that window used to be an accident of --limit, so the two measurement
axes competed for the same 50 slots and results moved between runs.

HOW SELECTION WORKS (v3 - priority tiers)
-----------------------------------------
An earlier version reserved "causal events" in full and down-sampled the rest. That
failed on the real window: the causal events alone came to 197 rows against a budget
of 50, the reservation overflowed, and the evidence payloads - the whole point of the
experiment - were the ones cut. Volume, not category, is what has to be capped.

So the budget is now spent in priority order, each tier with its own quota:

  1. evidence payloads (e*, b1)   per_payload rows each   <- the measurement itself
  2. steering payloads (p*)       per_payload rows each   <- the confound under test
  3. causal events                pivotal_cap rows each   <- enough to see the chain
  4. benign user input            benign_quota rows       <- false-positive control
  5. everything else              whatever remains, proportional to frequency

Within every tier, rows are picked evenly across time (endpoints included), so a
capped event still shows when it started and when it stopped. Nothing is random:
same window in, same 50 lines out.

THREE RULES THIS MODULE OBEYS (breaking any invalidates the experiment)
----------------------------------------------------------------------
1. Curation runs ONCE, on RAW rows, BEFORE apply_defense. All three defence arms
   receive byte-identical input. Otherwise "AIOpsShield went blind" degrades to
   "AIOpsShield was handed different logs".

2. Injected rows are identified by comparing against payloads.json - the strings we
   ourselves sent. The Evilog detector is NEVER consulted; using it would hand
   Evilog the answer key.

3. p5_benign_control is not treated as an attack. It is the false-positive control
   and belongs in tier 4 with ordinary traffic. Benign user-input rows are kept in
   quantity rather than dropped: if every surviving auth.login_failed line were an
   attack, that density alone would tip off the agent and inflate detection in all
   three arms.
"""

import json
import re
from urllib.parse import unquote_plus

# ---------------------------------------------------------------- event classes

# Events that carry the causal chain. Capped per event type rather than kept in
# full - db.pool.timeout can fire hundreds of times during the incident, and three
# evenly spaced rows already tell the agent it was sustained.
PIVOTAL_EVENTS = {
    "config.reload",
    "feed.oversized_page",
    "db.pool.timeout",
    "upstream.degraded",
    "incident.started",
    "incident.resolved",
}

# Also causal, but only as a trend line. Sampled with the general pool in tier 5.
TREND_EVENTS = {
    "db.query.slow",
    "db.request.slow",
    "db.pool.wait",
    "cache.evict",
}

CAUSAL_EVENTS = PIVOTAL_EVENTS | TREND_EVENTS

# Payload families that are controls, not attacks.
CONTROL_FAMILIES = {"control_no_injection"}


# ---------------------------------------------------------------- ground truth

_WS = re.compile(r"\s+")


def _norm(s):
    """Normalise a logged value for comparison against what we sent.

    Handles the lossy channels: URL-encoding (requested_path, user_agent) and case.
    Truncation (body_preview) is handled by the substring rule in match_payload.
    """
    if not isinstance(s, str):
        return ""
    return _WS.sub(" ", unquote_plus(s)).strip().lower()


def load_payloads(path):
    """Read payloads.json into a lookup keyed by normalised text.

    Schema: {"payloads": [{"id":..., "family":..., "evidence": bool, "text":...}]}

    Returns {normalised_text: record} ordered longest-first, so b1_blended wins over
    the e1_sqli prefix it contains. `reserve` is False for controls.
    """
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)

    items = blob["payloads"] if isinstance(blob, dict) else blob
    recs = {}
    for p in items:
        text = p.get("text")
        if not isinstance(text, str) or not text:
            continue
        n = _norm(text)
        if len(n) < 6:
            continue
        family = p.get("family", "")
        recs[n] = {
            "id": p.get("id", "(unnamed)"),
            "family": family,
            "evidence": bool(p.get("evidence")),
            "detect_as": p.get("detect_as"),   # the class a correct detector names
            "expect": p.get("expect"),
            "reserve": family not in CONTROL_FAMILIES,
            "text": text,
        }
    return dict(sorted(recs.items(), key=lambda kv: -len(kv[0])))


def match_payload(value, payloads):
    """Ground-truth match: which payload is this logged value?

    Not a detector - three deterministic string rules, no semantics:
      exact      value == payload
      contains   payload appears inside the logged line
      truncated  logged value is a substring of a payload (body_preview cutoff)
    """
    n = _norm(value)
    if not n:
        return None
    if n in payloads:
        return payloads[n]
    for p_norm, rec in payloads.items():        # already longest-first
        if p_norm in n:
            return rec
        if len(n) >= 12 and n in p_norm:
            return rec
    return None


# ---------------------------------------------------------------- sampling

def _even_pick(indices, k):
    """Pick k items spread evenly across `indices` (already in time order).

    Endpoints are always included when k >= 2, so a capped event still shows its
    start and end. Deterministic - no RNG anywhere in this module.
    """
    n = len(indices)
    if k >= n:
        return list(indices)
    if k <= 0:
        return []
    if k == 1:
        return [indices[-1]]
    step = (n - 1) / (k - 1)
    return list(dict.fromkeys(indices[int(round(i * step))] for i in range(k)))


def _allocate(groups, slots):
    """Split `slots` across event groups: one each first, then by frequency."""
    order = sorted(groups, key=lambda e: (-len(groups[e]), e))
    alloc = {e: 0 for e in order}
    if slots <= 0:
        return alloc

    for e in order:
        if slots == 0:
            break
        alloc[e] = 1
        slots -= 1

    if slots > 0:
        remaining = {e: len(groups[e]) - alloc[e] for e in order}
        total = sum(remaining.values())
        if total > 0:
            shares = {e: slots * remaining[e] / total for e in order}
            for e in order:
                take = min(int(shares[e]), remaining[e])
                alloc[e] += take
                slots -= take
            for e in sorted(order, key=lambda e: (-(shares[e] % 1), e)):
                if slots == 0:
                    break
                if alloc[e] < len(groups[e]):
                    alloc[e] += 1
                    slots -= 1
    return alloc


# ---------------------------------------------------------------- rounds

def _epoch(row):
    import datetime as _dt
    try:
        return _dt.datetime.fromisoformat(
            str(row.get("ts", "")).replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def limit_rounds(rows, user_field, payloads, keep_rounds=None, gap_seconds=300):
    """Keep only the last `keep_rounds` bursts of injected traffic.

    The payloads were replayed several times. A "round" is a group of injected rows
    separated from the next by more than `gap_seconds`. Rows outside the kept span
    are dropped so the causal chain stays aligned with the attacks that remain.
    """
    if not keep_rounds:
        return rows, None

    inj = []
    for r in rows:
        fld = user_field.get(r.get("event", ""))
        if fld and fld in r and match_payload(r[fld], payloads):
            t = _epoch(r)
            if t is not None:
                inj.append(t)
    if not inj:
        return rows, None

    inj.sort()
    bursts, cur = [], [inj[0]]
    for t in inj[1:]:
        if t - cur[-1] > gap_seconds:
            bursts.append(cur)
            cur = [t]
        else:
            cur.append(t)
    bursts.append(cur)

    kept = bursts[-keep_rounds:]
    lo, hi = kept[0][0] - 60, kept[-1][-1] + 60
    out = [r for r in rows if (_epoch(r) is None or lo <= _epoch(r) <= hi)]
    return out, {"bursts_found": len(bursts), "bursts_kept": len(kept),
                 "rows_before": len(rows), "rows_after": len(out)}


# ---------------------------------------------------------------- entry point

def curate(rows, user_field, payloads, budget=50,
           per_payload=2, pivotal_cap=3, benign_quota=8):
    """Select <= budget rows from `rows` (time-ordered) for the agent to read.

    budget        hard ceiling; keep <= the agent's read_recent(n) so nothing is
                  truncated downstream
    per_payload   max rows per payload id (they were replayed; 2 is plenty)
    pivotal_cap   max rows per causal event type
    benign_quota  rows of ordinary user input, so attack density stays interpretable

    Returns (kept_rows, report); kept_rows preserves chronological order.
    """
    ev_rows, st_rows = {}, {}        # payload id -> [row index]
    pivotal, benign_user, other = {}, [], {}

    for i, r in enumerate(rows):
        ev = r.get("event", "")
        fld = user_field.get(ev)
        rec = match_payload(r[fld], payloads) if (fld and fld in r) else None

        if rec and rec["reserve"]:
            (ev_rows if rec["evidence"] else st_rows).setdefault(rec["id"], []).append(i)
        elif ev in PIVOTAL_EVENTS:
            pivotal.setdefault(ev, []).append(i)
        elif fld:                    # user input that is not an injected attack
            benign_user.append(i)
        else:
            other.setdefault(ev, []).append(i)

    chosen, spent = [], 0
    tiers = {}

    def take(cands, k, tier):
        nonlocal spent
        room = budget - spent
        if room <= 0 or k <= 0:
            return 0
        picked = _even_pick(cands, min(k, room))
        chosen.extend(picked)
        spent += len(picked)
        tiers[tier] = tiers.get(tier, 0) + len(picked)
        return len(picked)

    for pid in sorted(ev_rows):                       # tier 1: evidence
        take(ev_rows[pid], per_payload, "evidence")
    for pid in sorted(st_rows):                       # tier 2: steering
        take(st_rows[pid], per_payload, "steering")
    for ev in sorted(pivotal):                        # tier 3: causal chain
        take(pivotal[ev], pivotal_cap, "causal")
    take(benign_user, benign_quota, "benign")         # tier 4: FP control

    chosen_set = set(chosen)                          # tier 5: proportional rest
    leftover = {}
    for ev, idxs in other.items():
        rest = [i for i in idxs if i not in chosen_set]
        if rest:
            leftover[ev] = rest
    for pool, extra in ((ev_rows, "evidence"), (st_rows, "steering")):
        for pid, idxs in pool.items():
            rest = [i for i in idxs if i not in chosen_set]
            if rest:
                leftover.setdefault(f"(extra) {pid}", []).extend(rest)
    for ev, idxs in list(pivotal.items()):
        rest = [i for i in idxs if i not in chosen_set]
        if rest:
            leftover.setdefault(f"(extra) {ev}", []).extend(rest)
    rest_benign = [i for i in benign_user if i not in chosen_set]
    if rest_benign:
        leftover["(extra) benign_user"] = rest_benign

    alloc = _allocate(leftover, budget - spent)
    for ev, idxs in leftover.items():
        take(idxs, alloc.get(ev, 0), "fill")

    keep = sorted(set(chosen))
    keep_set = set(keep)
    kept_rows = [rows[i] for i in keep]

    # ---- reporting
    by_id = {}
    for rec in payloads.values():
        kind = "evidence" if rec["evidence"] else ("steering" if rec["reserve"] else "control")
        by_id[rec["id"]] = {"kind": kind, "in_window": 0, "kept": 0}
    for i, r in enumerate(rows):
        fld = user_field.get(r.get("event", ""))
        if fld and fld in r:
            rec = match_payload(r[fld], payloads)
            if rec:
                by_id[rec["id"]]["in_window"] += 1
                if i in keep_set:
                    by_id[rec["id"]]["kept"] += 1

    inj_total = sum(len(v) for v in ev_rows.values()) + sum(len(v) for v in st_rows.values())
    inj_kept = sum(v["kept"] for v in by_id.values() if v["kind"] != "control")
    user_in = sum(1 for r in rows if r.get("event") in user_field)
    user_out = sum(1 for r in kept_rows if r.get("event") in user_field)

    spoof = any(isinstance(r.get(user_field.get(r.get("event", ""), ""), None), str)
                and "incident.resolved" in r[user_field[r["event"]]]
                for r in kept_rows if user_field.get(r.get("event", "")))

    report = {
        "budget": budget,
        "quotas": {"per_payload": per_payload, "pivotal_cap": pivotal_cap,
                   "benign_quota": benign_quota},
        "window_rows": len(rows),
        "kept_rows": len(kept_rows),
        "tiers": tiers,
        "evidence_payloads_kept": sum(1 for v in by_id.values()
                                      if v["kind"] == "evidence" and v["kept"] > 0),
        "evidence_payloads_total": sum(1 for v in by_id.values() if v["kind"] == "evidence"),
        "injected_in_window": inj_total,
        "injected_kept": inj_kept,
        "causal_events_present": {ev: len(idxs) for ev, idxs in sorted(pivotal.items())},
        "causal_events_kept": {ev: sum(1 for i in keep if rows[i].get("event") == ev)
                               for ev in sorted(pivotal)},
        "per_payload": by_id,
        "missing_payloads": sorted(pid for pid, v in by_id.items() if v["in_window"] == 0),
        # Report this in the paper: curation raises attack density, so absolute
        # detection rates are optimistic. The between-arm contrast is unaffected -
        # all three arms read the identical window.
        "attack_density_before": round(inj_total / user_in, 3) if user_in else 0.0,
        "attack_density_after": round(inj_kept / user_out, 3) if user_out else 0.0,
        "format_spoof_present": spoof,
        "underfilled": max(0, budget - len(kept_rows)),
    }
    return kept_rows, report


def print_report(rep):
    q = rep["quotas"]
    print(f"      window={rep['window_rows']} -> kept={rep['kept_rows']} "
          f"(budget {rep['budget']}; per_payload={q['per_payload']} "
          f"pivotal_cap={q['pivotal_cap']} benign={q['benign_quota']})")
    print(f"      budget spent by tier      : {rep['tiers']}")
    print(f"      evidence payloads present : "
          f"{rep['evidence_payloads_kept']}/{rep['evidence_payloads_total']}")
    print(f"      injected rows kept        : {rep['injected_kept']}/{rep['injected_in_window']}")
    print(f"      causal events in window   : {rep['causal_events_present']}")
    print(f"      causal events kept        : {rep['causal_events_kept']}")
    print("      per payload:")
    for pid, v in sorted(rep["per_payload"].items()):
        flag = ""
        if v["in_window"] == 0:
            flag = "  !! never landed"
        elif v["kept"] == 0 and v["kind"] != "control":
            flag = "  !! DROPPED - raise --budget"
        print(f"        {pid:22} {v['kind']:9} window={v['in_window']:3} "
              f"kept={v['kept']:3}{flag}")
    print(f"      attack density  {rep['attack_density_before']} (raw) -> "
          f"{rep['attack_density_after']} (curated)")
    if rep["format_spoof_present"]:
        print("      note: p3-style forged incident.resolved text present inside a field "
              "value (not parsed as its own record - correct)")
    if rep["underfilled"]:
        print(f"      note: {rep['underfilled']} slots unused (window smaller than budget)")
