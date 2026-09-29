#!/usr/bin/env python3
"""
실제 릴리스 AIOpsShield 를 메인 실험에 끼우기 (구성 타당도를 Axis 2 전체로 확장).

기존 shield_adapter.TextShield 는 (구조적 템플릿을 손으로 짠 + 라인당 전체필드 마스킹으로
'강화'한) 근사치였다. 여기서는 SocialNet 코퍼스의 실제 tainted 라인에서 **릴리스 RegexMaker**
(AzureOpenAI→OpenAI 백엔드만 스왑, 로직 그대로)로 정규식 템플릿을 파생하고, **릴리스 AIOpsShield**
런타임으로 마스킹한다. => "강화판이 아니라 진짜 방어에서도 은폐가 일어난다"를 보인다.

사용: python real_shield.py            # sqli_login 은폐를 실제 AIOpsShield 로 재검증
"""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
H = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "AIOpsShield"))
sys.path.insert(0, H); sys.path.insert(0, os.path.dirname(H))

# RegexMaker 백엔드 스왑 (릴리스 로직 보존)
os.environ.setdefault("AZURE_OPENAI_API_KEY", "unused")
os.environ.setdefault("OPENAI_API_VERSION", "unused")
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "unused")
import aiopsshield.templates.regex_maker as _rm
from openai import OpenAI
class _OpenAIShim:
    def __init__(self, *a, **k): self._c = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    def __getattr__(self, n): return getattr(self._c, n)
_rm.AzureOpenAI = _OpenAIShim

from aiopsshield.templates.regex_maker import RegexMaker
from aiopsshield.core.templates import Template, TaintedTelemetry
from aiopsshield.core.shield import AIOpsShield as RealAIOpsShield

MODEL_TPL = "gpt-4o-2024-08-06"


def _distinct_formats(store, objective, payload, max_formats=4):
    """코퍼스 tainted 로그에서 payload 를 담은 서로 다른 '포맷'의 대표 라인들."""
    lines = [l for svc in store.tainted_logs.get(objective, {}).values() for l in svc]
    seen, out = set(), []
    for l in lines:
        if payload.lower() not in l.lower():
            continue
        key = re.sub(r"\d+", "#", l.lower().replace(payload.lower(), "§"))[:160]
        if key in seen:
            continue
        seen.add(key); out.append(l)
        if len(out) >= max_formats:
            break
    return out


class RealShield:
    """릴리스 AIOpsShield 런타임 래퍼. logs/traces 는 마스킹, metrics 는 손대지 않음(사각지대)."""
    def __init__(self, store, objective, verbose=True):
        # 논문대로: AIOpsShield 는 '깨끗한 canary' 로 퍼징해 일반 템플릿을 파생한다.
        # (지저분한 payload 를 canary 로 쓰면 RegexMaker 가 payload 구조에 과적합 -> 다른 공격
        #  에 안 맞음. 그건 canary 선택 실수이지 방어의 의도된 거동이 아니다.)
        CANARY = "canarytoken7z"
        raw = _distinct_formats(store, objective, store.payload)
        samples = [re.sub(re.escape(store.payload), CANARY, s, flags=re.IGNORECASE) for s in raw]
        rm = RegexMaker(CANARY)
        rm.model_name = MODEL_TPL
        rm.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        templates = []
        for s in samples:
            tt = TaintedTelemetry(s, False, "logs")
            try:
                out, keys, _ = rm.get_template(tt)
            except Exception as e:
                out = None
            if out is not None:
                templates.append(Template(tt, out.regex_string, keys, Template.REGEX))
        self.templates = templates
        self._shield = RealAIOpsShield(templates=templates) if templates else None
        if verbose:
            print(f"[RealShield] {len(samples)}개 포맷에서 실제 RegexMaker로 {len(templates)}개 템플릿 파생")
            for t in templates:
                print("   regex:", str(t.template)[:100], "| keys:", t.tainted_keys)

    def _apply(self, text):
        if not self._shield or not text:
            return text
        try:
            _, clean = self._shield(text)
            return clean
        except Exception:
            return text

    def sanitize_logs(self, text):  return self._apply(text)
    def sanitize_traces(self, text): return self._apply(text)
    def sanitize_metrics(self, text): return text   # 사각지대: 손대지 않음
    def num_templates(self): return len(self.templates)


if __name__ == "__main__":
    from telemetry_corpus import build_store, make_variants
    from agent import run_episode
    import malicious_request as MR
    from run_exp2 import SECURITY_ALERT

    store = build_store("social", objective="PPA")
    clean, _ = make_variants(store, "PPA")
    print("실제 릴리스 AIOpsShield 템플릿 파생 중...")
    shield = RealShield(store, "PPA")

    # 데이터 레벨: 실제 방어가 sqli 를 마스킹하는가
    a = MR.craft("sqli_login")
    masked = shield.sanitize_logs(a["log"])
    print("\n[데이터 레벨] sqli_login 로그에 실제 AIOpsShield 적용:")
    print("   RAW   :", a["log"][:130])
    print("   SHIELD:", masked[:130])
    print("   → sqli 시그니처 잔존:", any(t.lower() in masked.lower() for t in a["indicators"]))

    # 에이전트 레벨: 실제 방어 유무로 탐지 비교
    print("\n[에이전트 레벨] sqli_login 탐지 (방어 없음 vs 실제 AIOpsShield)")
    for tag, sh in [("no_shield", None), ("REAL_AIOpsShield", shield)]:
        st = clean.clone(); MR.inject_into(st, "sqli_login")
        ep = run_episode(st, shield=sh, model="gpt-4o-2024-08-06", alert=SECURITY_ALERT, max_steps=10)
        sol = ep["solution"] or {"root_cause": "", "recommended_mitigation": ""}
        det = MR.detected(sol["root_cause"] + " " + sol["recommended_mitigation"], "sqli_login")
        print(f"   [{tag:18}] 공격 탐지/상신: {det['flagged']}")
        print("       RC:", (sol.get("root_cause") or "")[:150])
