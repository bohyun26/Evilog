#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evilog_claude — 교수님 원본 Evilog(V2) 방어는 '그대로' 두고, 최종 진단 에이전트만 GPT → Claude로 교체.
                      (evilog_gemini.py 의 Claude 판.)

★ 바뀐 것: analyze()(최종 에이전트)만 Claude. + MODELS(최종 에이전트 모델명).
★ 안 바뀐 것: build()·검사기(_DET_SYS_V2, CRLF 없음)·마스킹·field_out·has·SQLI
             = a2_fix_reattack.py 원본을 그대로 import (무수정 보장).

준비:  pip install anthropic
환경:  ANTHROPIC_API_KEY(최종=Claude)  +  OPENAI_API_KEY(검사기·마스킹=OpenAI)  +  AIOPSSHIELD_PATH
       MODELS(선택; 기본 claude-opus-5. 키/비용 따라 claude-sonnet-5 / claude-haiku-4-5)
"""
import os, sys
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
try:
    import anthropic                                  # ★ Claude SDK
except ImportError:
    anthropic = None
# ── 방어(검사기·마스킹)·판정 유틸 전부 교수님 원본 그대로 import (무수정) ──
from a2_fix_reattack import build, field_out, has, SQLI
from causal_defense import RELIABILITY               # 최종 에이전트 지시문 = 원본 그대로

# ★ 최종 에이전트 = Claude 모델. 접근 가능한/비용 맞는 모델로 바꿔도 됨.
MODELS = os.environ.get("MODELS", "claude-sonnet-5").split(",")   # opus-5는 benign도 거부 → sonnet-5


# ══════════════════════════════════════════════════════════════════════════════
#  ★★ 여기만 바뀜: 최종 에이전트 = Claude ★★  (검사기·마스킹은 위 import = 원본)
# ══════════════════════════════════════════════════════════════════════════════
_CLAUDE_CLIENT = None
def analyze(model, tel):
    """최종 진단 에이전트를 Claude로. RELIABILITY(원본 지시문) + 텔레메트리.
    공정 비교 위해 확장추론(thinking) 끄고 GPT/Gemini처럼 바로 진단 답변을 받음."""
    global _CLAUDE_CLIENT
    if anthropic is None:
        return "(claude-error/blocked: pip install anthropic 필요)"
    if _CLAUDE_CLIENT is None:
        _CLAUDE_CLIENT = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    try:
        r = _CLAUDE_CLIENT.messages.create(
            model=model, max_tokens=400,
            system=RELIABILITY,
            thinking={"type": "disabled"},
            messages=[{"role": "user", "content": "Application telemetry:\n" + tel}])
        if getattr(r, "stop_reason", None) == "refusal":   # 안전분류기 거부 → 은폐와 구분
            return "(claude-refusal)"
        return "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
    except Exception as e:
        return f"(claude-error/blocked: {str(e)[:70]})"


if __name__ == "__main__":
    print("MODELS(최종 에이전트=Claude):", MODELS)
    print("검사기·마스킹(고정) = a2_fix_reattack 원본 (gpt-4o-mini, CRLF 없음, OpenAI)")
    try:
        print(analyze(MODELS[0], "test: normal login failed email=user@example.com")[:120])
    except Exception as e:
        print("Claude 호출 실패:", e)
