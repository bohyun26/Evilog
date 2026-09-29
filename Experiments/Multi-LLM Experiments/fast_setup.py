#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fast_setup — 실험 공용 도우미: (1) 마스킹 템플릿 캐시  (2) 타임아웃 OpenAI 클라이언트.

★ 결과는 100% 동일. 바뀌는 건 "속도(빌드 캐시)"와 "안 멈춤(타임아웃)"뿐.
  - get_templates(): 마스킹 템플릿을 캐시(.mask_templates.jsonl)에서 즉시 로드.
                     없으면 앱 canary fuzz로 1회 build 후 저장 → 다음부턴 21분 build 생략.
                     저장/로드는 교수님 Template 클래스의 save/load_templates_jsonl 사용(안전).
  - oai(): timeout·retry 설정된 OpenAI 클라이언트 → 호출 하나가 영원히 멈추는 hang 방지.

캐시 무효화: 앱/canary 바뀌면 harness/.mask_templates.jsonl 삭제하거나 MASK_CACHE=0 로 실행.
"""
import os, time
import live_anchor as LA
from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted
from aiopsshield.core.templates import Template
from openai import OpenAI

_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".mask_templates.jsonl")


def oai(timeout=40, max_retries=2):
    """타임아웃(기본 40초)·재시도 있는 OpenAI 클라이언트. 멈춘 호출을 무한정 안 기다림."""
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"), timeout=timeout, max_retries=max_retries)


def get_templates(force=False):
    """마스킹 템플릿 반환. 캐시 있으면 즉시 로드(build 생략), 없으면 1회 build 후 저장."""
    use_cache = (not force) and os.getenv("MASK_CACHE", "1") == "1"
    if use_cache and os.path.exists(_CACHE):
        try:
            t = Template.load_templates_jsonl(_CACHE)
            if t:
                print(f"[fast_setup] 마스킹 템플릿 캐시 로드 {len(t)}개 → build 생략 (즉시)")
                return t
        except Exception as e:
            print(f"[fast_setup] 캐시 로드 실패({e}) → 새로 build")
    print("[fast_setup] 마스킹 템플릿 build (최초 1회, 앱 canary fuzz 필요)...")
    LA.fuzz(LA.CANARY); time.sleep(0.3); LA.dump_logs()
    et = ExtractTainted(LA.DUMP, LA.CANARY); et.load(LA.NS); et.extract_tainted()
    at = AbstractTainted(et); at.tm.model_name = "gpt-4o-2024-08-06"
    at.tm.client = oai()                       # 타임아웃 클라이언트 → build 중 hang 방지
    t = [x for x in at()[0] if x is not None]
    try:
        Template.save_templates_jsonl(_CACHE, t)
        print(f"[fast_setup] build 완료 {len(t)}개 → 캐시 저장. 다음 실험부턴 즉시 로드.")
    except Exception as e:
        print(f"[fast_setup] 캐시 저장 실패({e}) — 이번엔 재사용 안 됨(결과엔 영향 없음)")
    return t


if __name__ == "__main__":
    # 캐시 미리 만들어두기(선택): 한 번 돌려두면 이후 모든 실험이 build 생략
    t = get_templates()
    print(f"준비 완료: 템플릿 {len(t)}개, 캐시 = {_CACHE}")
