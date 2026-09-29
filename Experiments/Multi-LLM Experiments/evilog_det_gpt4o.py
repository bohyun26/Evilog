#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evilog_det_gpt4o — 교수님 원본 Evilog에서 '검사기'만 gpt-4o-mini → gpt-4o 로 교체.
                  프롬프트(_DET_SYS_V2, CRLF 없음)·마스킹·최종 에이전트 = 원본 그대로.

★ 바뀐 것: 검사기 판정 모델만 gpt-4o.   ★ 안 바뀐 것: 그 외 전부 (a2_fix_reattack import).
환경:  OPENAI_API_KEY + AIOPSSHIELD_PATH   |   DET_MODEL_GPT(선택, 기본 gpt-4o-2024-08-06)
"""
import os, sys, time
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
from openai import OpenAI
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted
from detect_then_mask import DetectThenMaskShield
# ── 검사기 프롬프트·부모 클래스·최종/마스킹 유틸 전부 원본 그대로 ──
from a2_fix_reattack import DetectThenMaskShieldV2, _DET_SYS_V2, analyze, field_out, has, SQLI, MODELS

DET_MODEL_GPT = os.environ.get("DET_MODEL_GPT", "gpt-4o-2024-08-06")


class DetGPT4o(DetectThenMaskShieldV2):
    """검사기만 gpt-4o. get_abstraction(주석부착)·마스킹은 부모(원본) 그대로."""
    def _detect(self, value):
        if value in self._cache:
            return self._cache[value]
        r = self._c.chat.completions.create(model=DET_MODEL_GPT, temperature=0, max_completion_tokens=8,
            messages=[{"role": "system", "content": _DET_SYS_V2}, {"role": "user", "content": value or ""}])
        v = (r.choices[0].message.content or "").strip()
        self._cache[value] = v
        return v


def build():
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    t = [x for x in at()[0] if x is not None]
    return DetectThenMaskShield(templates=t), DetGPT4o(templates=t)


if __name__ == "__main__":
    print("검사기 =", DET_MODEL_GPT, "(OpenAI, Evilog 프롬프트)  |  마스킹·최종 = 원본(OpenAI/GPT)")
    try:
        _, sh = build()
        for lab, s in [("benign", "alice@example.com"), ("SQLi", "admin' OR '1'='1' --"),
                       ("CRLF", "http://x/%0aSet-Cookie:sid=1")]:
            print(f"  {lab:8} -> {sh._detect(s)!r}")
    except Exception as e:
        print("점검 실패:", e)
