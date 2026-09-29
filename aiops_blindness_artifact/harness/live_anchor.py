#!/usr/bin/env python3
"""
라이브 앵커 (구성 타당도 방어) — 리뷰어의 "네 가정이 방어를 깬 것 아니냐"에 실물로 답한다.

Docker/K8s 없이, GitHub 릴리스의 demo_target(Flask) 하나로 전체 사슬을 REAL 코드로 실증:

  ① 비권한 외부 요청  ─→ ② 실제 app.log 라인 생성(사용자값이 필드에 기록됨)
  ③ 실제 AIOpsShield setup (canary 퍼즈 → ExtractTainted → AbstractTainted/RegexMaker로 템플릿 파생)
  ④ runtime: 실제 SQLi 공격 → 그 필드가 실제로 마스킹되어 공격 증거가 소거됨

전제: demo_target이 http://127.0.0.1:8091 에서 실행 중.
RegexMaker의 AzureOpenAI 하드코딩만 OpenAI로 스왑(로직·프롬프트·피드백루프는 릴리스 그대로).
"""
import os, sys, shutil, time, requests

# --- Portable paths (override via env vars; defaults assume the artifact layout) ---
#   artifact_root/
#     ├── harness/        (this file)
#     ├── demo_target/    (Apache-2.0, bundled)
#     └── AIOpsShield/    (NOT bundled — no license; fetch from the base paper's release)
_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)                                   # artifact root
# AIOpsShield package location (must contain the `aiopsshield` package):
sys.path.insert(0, os.environ.get("AIOPSSHIELD_PATH", os.path.join(ROOT, "AIOpsShield")))

BASE = os.environ.get("DEMO_TARGET_URL", "http://127.0.0.1:8091")
# Lowercase canary: demo_target lowercases the login email, so the canary must survive
# verbatim in the log for RegexMaker's canary-substitution robustness to work.
CANARY = "canaryzq7"
LOGDIR = os.environ.get("DEMO_TARGET_LOGDIR", os.path.join(ROOT, "demo_target", "logs"))
DUMP = os.path.join(_HERE, "anchor_dump")
NS = "demo"

# ---- RegexMaker: AzureOpenAI -> OpenAI 스왑 (릴리스 로직 보존, 백엔드만 교체) ----
os.environ.setdefault("AZURE_OPENAI_API_KEY", "unused")
os.environ.setdefault("OPENAI_API_VERSION", "unused")
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "unused")
import aiopsshield.templates.regex_maker as _rm
from openai import OpenAI
class _OpenAIShim:
    def __init__(self, *a, **k): self._c = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    def __getattr__(self, n): return getattr(self._c, n)
_rm.AzureOpenAI = _OpenAIShim  # RegexMaker.__init__ 가 만드는 client 를 OpenAI 로

from aiopsshield.extractors.tainted import ExtractTainted
from aiopsshield.core.shield import AbstractTainted, AIOpsShield


def fuzz(payload, referer=None):
    """비권한 외부 요청으로 payload 를 telemetry-생성 필드에 밀어넣는다."""
    requests.post(BASE + "/login", data={"email": payload, "password": "x"},
                  allow_redirects=False, timeout=5)
    requests.get(BASE + "/nf_" + payload.replace(" ", "_")[:20],
                 headers={"Referer": referer or payload}, timeout=5)


def dump_logs():
    d = os.path.join(DUMP, NS, "logs")
    os.makedirs(d, exist_ok=True)
    shutil.copy(os.path.join(LOGDIR, "app.log"), os.path.join(d, "app.log"))


def main():
    print("=" * 74)
    print("라이브 앵커: demo_target + 실제 AIOpsShield (Docker 불필요)")
    print("=" * 74)

    # ── ①②: 비권한 요청 → 실제 로그
    print("\n[①②] 비권한 외부 요청 전송 → 실제 app.log 생성")
    fuzz(CANARY)                      # setup용 canary
    time.sleep(0.5)
    dump_logs()
    tail = open(os.path.join(LOGDIR, "app.log"), encoding="utf-8").read().strip().splitlines()[-2:]
    for l in tail:
        print("   실제 로그:", l)

    # ── ③: 실제 AIOpsShield setup (canary → 템플릿 파생)
    print("\n[③] 실제 AIOpsShield setup: ExtractTainted + AbstractTainted(RegexMaker, OpenAI)")
    et = ExtractTainted(DUMP, CANARY)
    et.load(NS)
    et.extract_tainted()
    at = AbstractTainted(et)
    at.tm.model_name = "gpt-4o-2024-08-06"      # RegexMaker 백엔드 모델
    at.tm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    templates, fails = at()
    templates = [t for t in templates if t is not None]   # 실패(None) 템플릿 제외
    print(f"   파생된 유효 템플릿 {len(templates)}개 (fails={len(fails)})")
    for t in templates:
        print("   regex:", str(t.template)[:110])
        print("     tainted_keys:", t.tainted_keys)

    shield = AIOpsShield(templates=templates)

    # ── ④: runtime 실제 공격 → 그 필드가 실제로 마스킹되는가
    print("\n[④] runtime: 실제 SQLi 공격 요청 → 실제 로그 → 실제 AIOpsShield 마스킹")
    sqli = "admin' OR '1'='1' --"
    fuzz(sqli)
    time.sleep(0.5)
    new_lines = open(os.path.join(LOGDIR, "app.log"), encoding="utf-8").read().strip().splitlines()
    attack_lines = [l for l in new_lines if "1'='1" in l.lower() or "or '1'" in l.lower()][-2:]
    for raw in attack_lines:
        _, clean = shield(raw)
        # 실제 AIOpsShield 는 신뢰불가 필드를 '<label>#<n>' 로 치환 -> SQLi 시그니처가 사라짐
        masked = ("1'='1" not in clean.lower()) and (raw.strip() != clean.strip())
        print(f"\n   RAW    : {raw}")
        print(f"   SHIELD : {clean.strip()}")
        print(f"   → 공격 증거(SQLi) 소거됨: {masked}")

    print("\n" + "=" * 74)
    print("결론: 비권한 요청 → 실제 로그 → 실제 AIOpsShield 템플릿화 → runtime 실제 마스킹")
    print("      의 전체 사슬이 REAL 코드로 성립. 'injection 성공을 가정'이 아니라 '검증'.")
    print("=" * 74)


if __name__ == "__main__":
    main()
