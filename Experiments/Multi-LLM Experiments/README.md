# Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents

프롬프트 인젝션 방어를 위한 로그 마스킹이 애플리케이션 계층 공격의 증거까지 제거하여
AIOps 에이전트의 진단을 저해하는 문제를 실증하고, 이를 완화하는 방어 기법 **Evilog**를
제안한 논문의 재현 코드입니다.

> **용어 참고**: 코드에서 `DetectThenMaskShieldV2`(파일 `a2_fix_reattack.py`)로 구현된
> 방어가 논문의 **Evilog**입니다. 원본 방어 코드의 파일명은 그대로 두었습니다.

---

## 디렉터리 구성

```
evilog_release/
├── README.md
├── requirements.txt
├── .gitignore
│
├── (실험 스크립트) ─ 최종 에이전트별 탐지율 (논문 Table III)
│   ├── defense_paired_gpt4o_7.py     # 최종 = GPT-4o
│   ├── defense_paired_gemini_7.py    # 최종 = Gemini 2.5 Flash
│   └── defense_paired_claude_7.py    # 최종 = Claude Sonnet
│
├── (실험 스크립트) ─ 검사기 오탐율(FP)
│   └── fp_det_paired.py
│
├── (방어 모듈)
│   ├── fast_setup.py                 # 마스킹 템플릿 캐시 + 타임아웃
│   ├── evilog_gemini.py              # 최종 에이전트 = Gemini  (analyze)
│   ├── evilog_claude.py              # 최종 에이전트 = Claude  (analyze)
│   ├── evilog_det_gpt4o.py           # 검사기 = GPT-4o   (오탐 실험용)
│   ├── evilog_det_gemini.py          # 검사기 = Gemini
│   └── evilog_det_claude.py          # 검사기 = Claude
│
├── .mask_templates.jsonl             # 마스킹 템플릿 캐시(앱 없이 재현 가능)
│
└── results/                          # 실행 로그(실측값)
    ├── run_gpt7.txt / run_gemini7.txt / run_claude7.txt
    └── run_fp.txt

※ 실행에 필요한 원본 파일(a2_fix_reattack.py, detect_then_mask.py, live_anchor.py,
  demo_target/, AIOpsShield)은 포함되어 있지 않습니다. "의존성" 섹션을 참고하여
  원본 아티팩트에서 가져와 같은 폴더에 두거나 PYTHONPATH에 추가하세요.
```

---

## 1. 설치

```bash
pip install -r requirements.txt
```

## 2. 환경변수

```bash
export OPENAI_API_KEY=...       # 공격 생성 + 검사기(gpt-4o-mini) + GPT 최종 에이전트
export GOOGLE_API_KEY=...       # Gemini 최종/검사기
export ANTHROPIC_API_KEY=...    # Claude 최종/검사기
export AIOPSSHIELD_PATH=/path/to/AIOpsShield
```

> ⚠️ API 키는 절대 커밋하지 마세요. (`.gitignore`로 제외됨)
> `AIOpsShield`는 기존 방어[1]의 구현체로, 위 경로로 연결합니다.

## 3. 마스킹 템플릿 (최초 1회)

`.mask_templates.jsonl` 캐시가 포함되어 있어 **바로 실험을 재현**할 수 있습니다.
캐시가 없을 때만 `app/demo_target` 앱을 실행해 템플릿을 생성합니다.

---

## 4. 실험 1 — 최종 에이전트별 탐지율 (Table III)

동일한 공격(애플리케이션 계층 7종의 변형, 약 920개)을 **방어없음 / AIOpsShield / Evilog**
세 조건에 통과시켜, GPT-4o·Gemini·Claude가 각각 진단한 결과를 비교합니다.

```bash
python -u defense_paired_gpt4o_7.py   2>&1 | tee results/run_gpt7.txt
python -u defense_paired_gemini_7.py  2>&1 | tee results/run_gemini7.txt
python -u defense_paired_claude_7.py  2>&1 | tee results/run_claude7.txt
```

**결과 (각 로그의 '전체 최종 탐지율'):**

| 최종 모델 | 방어없음 | AIOpsShield | Evilog |
|---|---|---|---|
| GPT-4o | 89.6% | 36.1% | 97.6% |
| Gemini 2.5 Flash | 92.9% | 6.5% | 92.6% |
| Claude Sonnet | 99.6% | 55.2% | 96.8% |

→ 세 모델 모두 AIOpsShield에서 탐지율이 급감(은폐)하지만, Evilog에서는 92% 이상으로
회복·수렴합니다.

> **재현성 참고:** 공격 페이로드는 실행 시마다 LLM으로 새로 생성되므로(`temperature=0.9`),
> 정확한 수치는 실행마다 ±몇 %p 정도 달라질 수 있습니다. 그러나 **"방어없음 높음 →
> AIOpsShield 급감 → Evilog 회복·수렴"이라는 경향은 일관되게 재현**됩니다.
> `results/`의 로그는 저자가 실제로 얻은 결과 기록입니다.

## 5. 실험 2 — 검사기 오탐율 (False Positive)

정상 입력 120건을 검사기가 공격으로 오판하는지 측정합니다.

```bash
python -u fp_det_paired.py 2>&1 | tee results/run_fp.txt
```

**결과:** Evilog의 검사기(GPT-4o-mini)는 정상 입력 120건에 대해 **오탐율 0%** 를 기록합니다.
(즉, 공격 탐지 성능을 확보하면서도 정상 입력을 공격으로 분류하지 않습니다.)

> **재현성 참고:** 정상 입력 또한 실행 시마다 새로 생성되므로 개별 값은 달라질 수 있으나,
> Evilog 검사기가 정상 입력을 공격으로 오판하지 않는다는 결과는 일관되게 재현됩니다.

---

## 의존성 (원본 아티팩트에서 가져올 것)

이 저장소의 스크립트는 **원본 AIOps 방어 아티팩트**의 파일들을 그대로 사용합니다.
아래 원본 파일들을 **이 스크립트들과 같은 폴더에 두거나** `PYTHONPATH`에 추가해야 실행됩니다.

원본 아티팩트에서 가져와야 하는 파일:
- `a2_fix_reattack.py` : Evilog 로직(`DetectThenMaskShieldV2`) + 검사기 프롬프트 + GPT `analyze`
- `detect_then_mask.py` : detect-then-mask 기반 클래스
- `live_anchor.py` : canary / 마스킹 템플릿 학습
- `demo_target/` : 로그를 생성하는 Flask 웹 애플리케이션
- `AIOpsShield` : 기존 마스킹 방어[1] — 코드는 포함하지 않으며 `AIOPSSHIELD_PATH`로 경로만 연결

> 위 원본 파일들은 본 저장소에서 수정하지 않았습니다. 원본 아티팩트의 것을 그대로 사용하세요.

## 참고문헌

[1] D. Pasquini et al., "When AIOps Become 'AI Oops': Subverting LLM-driven IT
Operations via Telemetry Manipulation," USENIX Security 2026.
