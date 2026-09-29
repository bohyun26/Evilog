#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evilog_det_claude — 교수님 원본 Evilog에서 '검사기'만 gpt-4o-mini → Claude 로 교체.
                   프롬프트(_DET_SYS_V2, CRLF 없음)·마스킹·최종 에이전트 = 원본 그대로.

★ 바뀐 것: 검사기 판정 모델만 Claude.   ★ 안 바뀐 것: 그 외 전부 (a2_fix_reattack import).
준비:  pip install anthropic
환경:  ANTHROPIC_API_KEY(검사기) + OPENAI_API_KEY(마스킹·최종) + AIOPSSHIELD_PATH
       DET_MODEL_CLAUDE(선택, 기본 claude-opus-5; 키/비용 따라 claude-sonnet-5 / claude-haiku-4-5)
"""
import os, sys, time
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
from openai import OpenAI
try:
    import anthropic
except ImportError:
    anthropic = None
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted
from detect_then_mask import DetectThenMaskShield
from a2_fix_reattack import DetectThenMaskShieldV2, _DET_SYS_V2, analyze, field_out, has, SQLI, MODELS

DET_MODEL_CLAUDE = os.environ.get("DET_MODEL_CLAUDE", "claude-sonnet-5")   # opus-5는 benign도 거부 → sonnet-5


class DetClaude(DetectThenMaskShieldV2):
    """검사기만 Claude(확장추론 끔=바로 판정). 마스킹·주석부착은 부모(원본, OpenAI) 그대로."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._cl = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY")) if anthropic else None

    def _detect(self, value):
        if value in self._cache:
            return self._cache[value]
        if self._cl is None:
            v = ""                                   # anthropic 미설치 → 빈 응답(놓침 집계). pip install anthropic
        else:
            try:
                r = self._cl.messages.create(model=DET_MODEL_CLAUDE, max_tokens=64,
                    system=_DET_SYS_V2, thinking={"type": "disabled"},
                    messages=[{"role": "user", "content": value or ""}])
                if getattr(r, "stop_reason", None) == "refusal":
                    v = ""                           # 안전분류기 거부 → 빈 응답(놓침 집계)
                else:
                    v = "".join(b.text for b in r.content if getattr(b, "type", None) == "text").strip()
            except Exception:
                v = ""
        self._cache[value] = v
        return v


def build():
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    t = [x for x in at()[0] if x is not None]
    return DetectThenMaskShield(templates=t), DetClaude(templates=t)


if __name__ == "__main__":
    print("검사기 =", DET_MODEL_CLAUDE, "(Claude, Evilog 프롬프트)  |  마스킹·최종 = 원본(OpenAI/GPT)")
    try:
        _, sh = build()
        for lab, s in [("benign", "alice@example.com"), ("SQLi", "admin' OR '1'='1' --"),
                       ("CRLF", "http://x/%0aSet-Cookie:sid=1")]:
            print(f"  {lab:8} -> {sh._detect(s)!r}")
    except Exception as e:
        print("점검 실패:", e)
