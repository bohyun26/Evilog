#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final diagnostic agent = Gemini.

The detector and masking are the original Evilog defense (imported unchanged from
a2_fix_reattack); only the final agent's analyze() uses Gemini.

Env: GOOGLE_API_KEY (final agent) + OPENAI_API_KEY (detector/masking) + AIOPSSHIELD_PATH
"""
import os, sys
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
import google.generativeai as genai
from a2_fix_reattack import build, field_out, has, SQLI
from causal_defense import RELIABILITY

MODELS = os.environ.get("MODELS", "gemini-2.5-flash").split(",")


def analyze(model, tel):
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    m = genai.GenerativeModel(model, system_instruction=RELIABILITY)
    # Relax safety filters for research: the input is attack telemetry to analyze, not to act on.
    safety = [{"category": c, "threshold": "BLOCK_NONE"} for c in (
        "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT")]
    try:
        r = m.generate_content(
            "Application telemetry:\n" + tel,
            generation_config={"temperature": 0, "max_output_tokens": 1024},
            safety_settings=safety)
        return (r.text or "")
    except Exception as e:
        return f"(gemini-error/blocked: {str(e)[:70]})"


if __name__ == "__main__":
    print("final agent (Gemini):", MODELS)
    try:
        print(analyze(MODELS[0], "test: normal login failed email=user@example.com")[:120])
    except Exception as e:
        print("Gemini call failed:", e)
