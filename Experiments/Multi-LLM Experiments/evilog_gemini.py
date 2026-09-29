#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evilog_gemini — 교수님 원본 Evilog(V2) 방어는 '그대로' 두고, 최종 진단 에이전트만 GPT → Gemini로 교체.

★ 바뀐 것: analyze()(최종 에이전트)만 Gemini. + MODELS(최종 에이전트 모델명).
★ 안 바뀐 것: build()·검사기(_DET_SYS_V2, CRLF 없음)·마스킹·field_out·has·SQLI
             = a2_fix_reattack.py 원본을 그대로 import (한 줄도 재정의 안 함 → 무수정 보장).
  (내 v3/v4 방어가 아니라 '순수 Evilog 원본' + 최종만 Gemini.)

준비:  pip install google-generativeai
환경:  GOOGLE_API_KEY(최종=Gemini)  +  OPENAI_API_KEY(검사기·마스킹=OpenAI)  +  AIOPSSHIELD_PATH
"""
import os, sys
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
import google.generativeai as genai                 # ★ Gemini SDK (최종 에이전트용)
# ── 방어(검사기·마스킹)·판정 유틸 전부 교수님 원본 그대로 import (무수정) ──
from a2_fix_reattack import build, field_out, has, SQLI
from causal_defense import RELIABILITY               # 최종 에이전트 지시문 = 원본 그대로

# ★ 최종 에이전트 = Gemini 모델. 접근 가능한 모델로 바꿔도 됨(gemini-1.5-flash/pro 등).
MODELS = os.environ.get("MODELS", "gemini-2.5-flash").split(",")   # 2.0-flash 은퇴 → 2.5-flash


# ══════════════════════════════════════════════════════════════════════════════
#  ★★ 여기만 바뀜: 최종 에이전트 = Gemini ★★  (검사기·마스킹은 위 import = 원본)
# ══════════════════════════════════════════════════════════════════════════════
def analyze(model, tel):
    """최종 진단 에이전트를 Gemini로. RELIABILITY(원본 지시문) + 텔레메트리."""
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    m = genai.GenerativeModel(model, system_instruction=RELIABILITY)
    # 공격 페이로드를 분석만 하므로 안전필터 완화(연구용). 없으면 Gemini가 로그를 막을 수 있음.
    safety = [{"category": c, "threshold": "BLOCK_NONE"} for c in (
        "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT")]
    try:
        r = m.generate_content(
            "Application telemetry:\n" + tel,
            generation_config={"temperature": 0, "max_output_tokens": 1024},  # 2.5-flash는 thinking 소비 → 여유
            safety_settings=safety)
        return (r.text or "")
    except Exception as e:
        return f"(gemini-error/blocked: {str(e)[:70]})"


if __name__ == "__main__":
    print("MODELS(최종 에이전트=Gemini):", MODELS)
    print("검사기·마스킹(고정) = a2_fix_reattack 원본 (gpt-4o-mini, CRLF 없음, OpenAI)")
    try:
        print(analyze(MODELS[0], "test: normal login failed email=user@example.com")[:120])
    except Exception as e:
        print("Gemini 호출 실패:", e)
