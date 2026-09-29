#!/usr/bin/env python3
"""
보강 — '치료'(방어 회복)도 진짜 다단계 에이전트로 검증 (질병-치료 비대칭 제거).

agentic_rca.py는 은폐(질병)가 진짜 도구호출 에이전트에도 성립함을 보였다(SQLi 특정 0/5). 그런데 방어 회복
(AnomalyAware=증거 보존→탐지 회복, A2=신뢰 주석→탐지 회복)은 아직 단일 LLM 호출로만 쟀다 = "병은 진짜
에이전트로, 약은 토이로 봤다"는 비대칭. 그래서 같은 능동 다단계 에이전트에게 4조건의 텔레메트리를 주고
SQLi를 다시 짚는지 본다:
  no_shield(원문) / AIOpsShield(마스킹→눈멂) / AnomalyAware(증거 보존) / A2(탐지-후-마스킹 주석).
기대: no_shield·AnomalyAware·A2 = 능동 에이전트도 SQLi 특정 회복, AIOpsShield = 눈멂. (존재증명이 에이전트 레벨에서도 성립하나?)
"""
import os, sys, time
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H)
from openai import OpenAI
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted, AIOpsShield
from anomaly_defense import AnomalyAwareShield
from detect_then_mask import DetectThenMaskShield
# 같은 능동 에이전트 루프·판정·볼륨 생성을 그대로 재사용(단일 진실원)
from agentic_rca import agentic_diagnose, classify, generate_volume, APP_LOG, MODELS

NREPEAT = int(os.environ.get("NREPEAT", "3"))


def build_shields():
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    t = [x for x in at()[0] if x is not None]
    return {"AIOpsShield": AIOpsShield(templates=t),
            "AnomalyAware": AnomalyAwareShield(templates=t),
            "A2(detect-then-mask)": DetectThenMaskShield(templates=t)}


def main():
    print("=" * 92)
    print("방어 회복도 진짜 다단계 에이전트로 검증 (질병은 agentic_rca, 치료는 여기 = 비대칭 제거)")
    print("=" * 92)
    shields = build_shields()
    generate_volume()
    nlines = len(open(APP_LOG, encoding="utf-8").read().splitlines())
    print(f"\n  app.log 볼륨: {nlines}줄 (benign 로그인 실패 + SQLi 묻힘). 능동 에이전트가 도구로 조사.")

    # 조건: (라벨, shield_on, shield객체)  — 같은 능동 루프에 텔레메트리 파이프만 교체
    conditions = [("no_shield", False, None),
                  ("AIOpsShield", True, shields["AIOpsShield"]),
                  ("AnomalyAware(evidence-preserve)", True, shields["AnomalyAware"]),
                  ("A2(detect-then-mask)", True, shields["A2(detect-then-mask)"])]

    agg = {}
    for model in MODELS:
        for label, son, sh in conditions:
            strict = tools = 0
            for _ in range(NREPEAT):
                out, nc = agentic_diagnose(model, son, sh)
                s, _g = classify(out); strict += int(s); tools += nc
            agg[(model, label)] = (strict, tools)

    print("\n  ---- 능동 다단계 에이전트가 SQLi를 '특정'해 짚나 (탐지수/N, 평균 도구호출) ----")
    for model in MODELS:
        print(f"\n    [{model}]")
        for label, _son, _sh in conditions:
            s, t = agg[(model, label)]
            mark = "✅ 회복" if (label != "AIOpsShield" and s >= NREPEAT - (NREPEAT // 3)) else ("❌ 눈멂" if s == 0 else "부분")
            print(f"      {label:34} SQLi특정 {s}/{NREPEAT}  (도구 {t/NREPEAT:.1f}회)  {mark if label!='no_shield' else '(기준선)'}")

    print("\n  해석: 은폐(질병)뿐 아니라 방어 회복(치료)도 '단일 호출'이 아니라 '진짜 능동 다단계 에이전트'로 검증.")
    print("        AnomalyAware(증거 보존)·A2(신뢰 주석)가 능동 에이전트에도 SQLi 탐지를 되살리면, 존재증명이 에이전트 레벨에서 성립.")
    print("=" * 92)


if __name__ == "__main__":
    main()
