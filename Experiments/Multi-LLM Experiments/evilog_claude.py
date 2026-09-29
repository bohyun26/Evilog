#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final diagnostic agent = Claude.

The detector and masking are the original Evilog defense (imported unchanged from
a2_fix_reattack); only the final agent's analyze() uses Claude.

Env: ANTHROPIC_API_KEY (final agent) + OPENAI_API_KEY (detector/masking) + AIOPSSHIELD_PATH
     MODELS (optional; default claude-sonnet-5)
"""
import os, sys
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
try:
    import anthropic
except ImportError:
    anthropic = None
from a2_fix_reattack import build, field_out, has, SQLI
from causal_defense import RELIABILITY

MODELS = os.environ.get("MODELS", "claude-sonnet-5").split(",")


_CLAUDE_CLIENT = None
def analyze(model, tel):
    # Extended thinking is disabled so the response format matches GPT/Gemini for a fair comparison.
    global _CLAUDE_CLIENT
    if anthropic is None:
        return "(claude-error/blocked: install the anthropic package)"
    if _CLAUDE_CLIENT is None:
        _CLAUDE_CLIENT = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    try:
        r = _CLAUDE_CLIENT.messages.create(
            model=model, max_tokens=400,
            system=RELIABILITY,
            thinking={"type": "disabled"},
            messages=[{"role": "user", "content": "Application telemetry:\n" + tel}])
        if getattr(r, "stop_reason", None) == "refusal":   # safety refusal, kept distinct from concealment
            return "(claude-refusal)"
        return "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
    except Exception as e:
        return f"(claude-error/blocked: {str(e)[:70]})"


if __name__ == "__main__":
    print("final agent (Claude):", MODELS)
    try:
        print(analyze(MODELS[0], "test: normal login failed email=user@example.com")[:120])
    except Exception as e:
        print("Claude call failed:", e)
