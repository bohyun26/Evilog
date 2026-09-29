# Fragment-Aware Defense for the A2 Detector

A pre-processing layer that protects the A2 (detect-then-mask) detector against **fragmentation attacks**.

## Problem

The A2 detector classifies each log field value **independently**. An attacker can split a payload
into several fragments and inject them separately. Each fragment looks harmless on its own, so
detection drops sharply. When the fragments are joined back together, the original payload is
restored, and the same detector flags it almost perfectly. The weakness is the per-value inspection
structure, not the detector itself.

## Defense: session buffer, sliding window and lossless reconstruction

```
fragment -> [append to per-session buffer -> build reconstruction candidates] -> detector -> verdict
```

- The underlying detector is wrapped **unchanged**: same prompt, same model. The layer only adds
  reconstruction.
- Each session keeps its most recent fragments in a bounded buffer (`max_buffer`).
- For every incoming fragment, the layer checks two kinds of candidates:
  - the fragment itself;
  - reconstructions of the buffer tail, one for each window size and join string.

  If any candidate is classified as an attack, the session is flagged.
- The default join is **lossless** (`"".join`): it rebuilds exactly what the attacker sent, in the
  order it was sent. Joining benign fragments gives back the benign original, so reconstruction does
  not create attacks that weren't there, and the false-positive rate stays low.
- Adding `" "` or `"\n"` to `join_variants` also covers attacks that split the payload at separators,
  but raises the false-positive risk.
- The sliding window caps memory and cost. It also keeps detection working when unrelated values are
  interleaved between fragments.

## Components (`fragment_aware_defense.py`)

| Name | Description |
|---|---|
| `DETECTOR_SYSTEM_PROMPT` | A2 detector system prompt (V2, attack-precedence taxonomy) |
| `classify_verdict(verdict)` | Normalizes a raw detector verdict into `benign` / `instruction` / `attack` |
| `LLMDetector` | The A2 detector: one LLM call per value, returns the raw verdict string. `use_cache=False` (default) makes every call independent, which matches the evaluation setting. |
| `FragmentAwareA2` | The defense layer (see parameters below) |
| `build_default(model, **kw)` | Builds a `FragmentAwareA2` that wraps `LLMDetector` |

### `FragmentAwareA2` parameters

| Parameter | Default | Description |
|---|---|---|
| `detect_fn` | – | `str -> raw verdict` (for example, an `LLMDetector` instance) |
| `classify_fn` | `classify_verdict` | raw verdict → `benign` / `instruction` / `attack` |
| `window_sizes` | `None` | Sliding-window sizes. `None` reconstructs the whole buffer (cheapest: 2 detector calls per fragment). |
| `join_variants` | `("",)` | Join strings used for reconstruction. The default is lossless joining only, which gives the lowest false-positive rate. |
| `max_buffer` | `32` | Maximum number of fragments kept per session |

Methods:
- `detect_fragment(fragment, session_id)`: adds the fragment to the session buffer, then runs the
  detector on the fragment and on each reconstruction. Returns the combined verdict and the candidate
  that triggered it.
- `reset(session_id=None)`: clears one session's buffer, or every session's buffer when `session_id`
  is `None`.

### Return value of `detect_fragment`

| Key | Meaning |
|---|---|
| `aggregated_detected` | Final decision of the defense layer (`True` = attack) |
| `aggregated_bucket` | `attack` if detected, otherwise the fragment's own bucket |
| `fragment_verdict_raw`, `fragment_bucket` | Verdict for the fragment alone (the undefended A2 result) |
| `trigger_kind`, `trigger_value`, `trigger_raw` | The first candidate classified as an attack |
| `reconstruction_triggered` | `True` if the attack was caught only through reconstruction |
| `detector_calls` | Number of detector calls for this fragment (runtime overhead) |
| `candidates_checked` | Every candidate checked, with its verdict |
| `session_id`, `fragment`, `buffer_size` | Input and buffer state |

## Usage

Requirements: Python 3.9+ and `openai`.

```bash
pip install openai
export OPENAI_API_KEY=...
```

```python
from fragment_aware_defense import build_default

layer = build_default()                      # wraps the LLM-based A2 detector
result = layer.detect_fragment("<fragment>", session_id="req-123")
if result["aggregated_detected"]:
    ...  # mask / alert
```

You can plug in any detector:

```python
from fragment_aware_defense import FragmentAwareA2, classify_verdict

layer = FragmentAwareA2(my_detect_fn, classify_verdict,
                        window_sizes=[2, 4, 8], join_variants=("", " "))
```

## Offline demo

The demo runs without an API key. It uses a toy detector that flags only the complete SQL injection
payload:

```bash
python fragment_aware_defense.py
```

```
frag[0] "admin' O"   fragment=benign    detected=False trigger=None calls=1
frag[1] "R '1'="     fragment=benign    detected=False trigger=None calls=2
frag[2] "'1' --"     fragment=benign    detected=True trigger=reconstruct(w=3,join='') calls=2
```

No single fragment is detected on its own. The attack is caught once the reconstructed buffer
contains the full payload.
