#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evilog_det_gemini — 교수님 원본 Evilog에서 '검사기'만 gpt-4o-mini → Gemini 로 교체.
                   프롬프트(_DET_SYS_V2, CRLF 없음)·마스킹·최종 에이전트 = 원본 그대로.

★ 바뀐 것: 검사기 판정 모델만 Gemini.   ★ 안 바뀐 것: 그 외 전부 (a2_fix_reattack import).
준비:  pip install google-generativeai
환경:  GOOGLE_API_KEY(검사기) + OPENAI_API_KEY(마스킹·최종) + AIOPSSHIELD_PATH
       DET_MODEL_GEMINI(선택, 기본 gemini-2.0-flash; thinking 모델은 빈 응답 위험 → flash 권장)
"""
import os, sys, time
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
from openai import OpenAI
import google.generativeai as genai
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted
from detect_then_mask import DetectThenMaskShield
from a2_fix_reattack import DetectThenMaskShieldV2, _DET_SYS_V2, analyze, field_out, has, SQLI, MODELS

DET_MODEL_GEMINI = os.environ.get("DET_MODEL_GEMINI", "gemini-2.5-flash")   # 2.0-flash 은퇴 → 2.5-flash
_GEM_SAFETY = [{"category": c, "threshold": "BLOCK_NONE"} for c in (
    "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT")]


class DetGemini(DetectThenMaskShieldV2):
    """검사기만 Gemini. 마스킹·주석부착은 부모(원본, OpenAI) 그대로."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
        self._gem = genai.GenerativeModel(DET_MODEL_GEMINI, system_instruction=_DET_SYS_V2)

    def _detect(self, value):
        if value in self._cache:
            return self._cache[value]
        try:
            r = self._gem.generate_content(value or "",
                generation_config={"temperature": 0, "max_output_tokens": 512},  # 2.5-flash thinking 여유(판정문은 짧음)
                safety_settings=_GEM_SAFETY)
            v = (r.text or "").strip()
        except Exception:
            v = ""                                   # 차단/에러 → 빈 응답(=검사기 놓침으로 집계)
        self._cache[value] = v
        return v


def build():
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    t = [x for x in at()[0] if x is not None]
    return DetectThenMaskShield(templates=t), DetGemini(templates=t)


if __name__ == "__main__":
    print("검사기 =", DET_MODEL_GEMINI, "(Gemini, Evilog 프롬프트)  |  마스킹·최종 = 원본(OpenAI/GPT)")
    try:
        _, sh = build()
        for lab, s in [("benign", "alice@example.com"), ("SQLi", "admin' OR '1'='1' --"),
                       ("CRLF", "http://x/%0aSet-Cookie:sid=1")]:
            print(f"  {lab:8} -> {sh._detect(s)!r}")
    except Exception as e:
        print("점검 실패:", e)
