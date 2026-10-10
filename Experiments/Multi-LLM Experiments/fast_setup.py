#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared helpers: (1) a masking-template cache and (2) an OpenAI client with a timeout.

Results are unchanged; only speed (build cache) and robustness (timeout) improve.
  - get_templates(): load masking templates from the cache (.mask_templates.jsonl) if present;
                     otherwise build them once via canary fuzzing and save the cache.
  - oai(): an OpenAI client with timeout/retry so a single hanging call cannot stall a run.

To invalidate the cache: delete .mask_templates.jsonl or run with MASK_CACHE=0.
"""
import os, time
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted
from aiopsshield.core.templates import Template
from openai import OpenAI

_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".mask_templates.jsonl")


def oai(timeout=40, max_retries=2):
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"), timeout=timeout, max_retries=max_retries)


def get_templates(force=False):
    use_cache = (not force) and os.getenv("MASK_CACHE", "1") == "1"
    if use_cache and os.path.exists(_CACHE):
        try:
            t = Template.load_templates_jsonl(_CACHE)
            if t:
                print(f"[fast_setup] loaded {len(t)} cached masking templates (build skipped)")
                return t
        except Exception as e:
            print(f"[fast_setup] cache load failed ({e}) -> rebuilding")
    print("[fast_setup] building masking templates (one-time; requires the app for canary fuzzing)...")
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = oai()
    t = [x for x in at()[0] if x is not None]
    try:
        Template.save_templates_jsonl(_CACHE, t)
        print(f"[fast_setup] built {len(t)} templates and saved the cache")
    except Exception as e:
        print(f"[fast_setup] cache save failed ({e}); results are unaffected")
    return t


if __name__ == "__main__":
    t = get_templates()
    print(f"ready: {len(t)} templates, cache = {_CACHE}")
