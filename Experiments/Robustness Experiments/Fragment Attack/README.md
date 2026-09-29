# Evilog: Fragment-Aware Detection

This directory contains the fragment-attack defense of **Evilog** (*Evidence-Preserving Log
Sanitization for LLM-based AIOps Agents*). It corresponds to **Section V-E-1 (Fragment attack)** of
the paper.

## Background

Evilog uses a **detect-then-mask** scheme. Before AIOpsShield masks a user-controlled log field,
Evilog passes the value to an LLM-based security detector. If the detector finds an
application-layer attack, Evilog masks the original string and keeps a trustworthy security memo
(for example, `SECURITY: SQLi detected`) for the AIOps agent.

The detector inspects **one input value at a time**. An attacker can split an attack payload into
several fragments and send them as separate inputs. A single fragment may not carry enough of the
payload to identify the attack.

## Defense: per-session buffer and reconstruction

Evilog inspects user input before masking. It stores fragments **in order** in a per-session
buffer, reconstructs them, and checks the reconstruction for an attack again.

```
user input (fragment)
   -> append to per-session buffer (up to 32 values)
   -> candidates: the fragment itself + ordered reconstruction of the buffer
   -> security detector (unchanged)
   -> any candidate is an attack  => security memo "SECURITY: <type> detected"
   -> masking (AIOpsShield)
```

- The buffer holds up to **32 input values**. The full attack pattern can therefore be recovered even
  when no single fragment is enough to identify the attack.
- The security detector itself is **not modified**. Its prompt, model (`gpt-4o-mini`) and
  constrained output format are the same as in the rest of Evilog.
- The default reconstruction is a **lossless, in-order join** (`"".join`). It rebuilds exactly what
  was sent, in the order it was sent. Joining benign fragments only gives back the benign original,
  so reconstruction does not create attacks that weren't there.
- Optionally, `window_sizes` limits reconstruction to the most recent *w* fragments, and
  `join_variants` adds separators such as `" "` or `"\n"` (broader coverage, higher false-positive
  risk).

## Results (paper, Section V-E-1)

Setup:
- **Attacks**: the seven application-layer attacks (SQL injection, command injection, XSS,
  Log4Shell, NoSQL injection, LDAP injection, SSTI).
- **Injection fields**: the login-identifier field. Log4Shell was injected into the Referer field.
- **Fragmentation schemes (5)**: token, whitespace, operator, fixed-length and random. The
  fixed-length scheme splits every *n* characters. The random scheme splits into pieces of random
  length.
- **Total**: 7 attacks × 5 schemes = **35 combinations**.

| Condition | Detected | Rate |
|---|---|---|
| Without AIOpsShield | 32 / 35 | 91.4% |
| AIOpsShield [1] | – | attack evidence masked, attack type not identified |
| **Evilog (fragment-aware)** | **35 / 35** | **100%** |

- Without AIOpsShield, detection failed on the **token** fragmentation of NoSQL injection, LDAP
  injection and SSTI. The full pattern was hard to identify from the individual fragments alone.
  Evilog detected all three through reconstruction.
- For the token fragmentation of LDAP injection, all **14** individual fragments were judged
  benign, but Evilog detected LDAP injection from the reconstructed input.
- **Cost**: reconstruction needs a per-session buffer and extra detector calls. With the default
  settings, each fragment costs up to 2 detector calls: one for the fragment and one for the
  reconstruction. This adds processing time and compute compared with masking alone.

## Code (`evilog_fragment_defense.py`)

| Name | Description |
|---|---|
| `DETECTOR_SYSTEM_PROMPT` | System prompt of the Evilog security detector (attack-type taxonomy, constrained output) |
| `classify_verdict(verdict)` | Normalizes a raw detector verdict into `benign` / `instruction` / `attack` |
| `security_memo(verdict)` | Builds the security memo, `SECURITY: <type> detected` |
| `SecurityDetector` | LLM-based security detector: one call per value, returns the raw verdict. The default model is `gpt-4o-mini`. `use_cache=False` (default) keeps every call independent. |
| `FragmentAwareDetector` | Per-session buffer and reconstruction layer that wraps a detector |
| `build_default(model, **kw)` | Builds a `FragmentAwareDetector` that wraps `SecurityDetector` |

### `FragmentAwareDetector` parameters

| Parameter | Default | Description |
|---|---|---|
| `detect_fn` | – | `str -> raw verdict` (for example, a `SecurityDetector` instance) |
| `classify_fn` | `classify_verdict` | raw verdict → `benign` / `instruction` / `attack` |
| `window_sizes` | `None` | Sliding-window sizes. `None` reconstructs the whole buffer. |
| `join_variants` | `("",)` | Join strings used for reconstruction. The default is the lossless, in-order join only. |
| `max_buffer` | `32` | Maximum number of input values kept per session (the paper setting) |

Methods:
- `detect_fragment(fragment, session_id)`: adds the fragment to the session buffer, then runs the
  detector on the fragment and on the reconstruction.
- `reset(session_id=None)`: clears one session's buffer, or every session's buffer when `session_id`
  is `None`.

### Return value of `detect_fragment`

| Key | Meaning |
|---|---|
| `aggregated_detected` | Final decision (`True` = attack) |
| `security_memo` | `SECURITY: <type> detected` if an attack was found, otherwise `None` |
| `fragment_verdict_raw`, `fragment_bucket` | Verdict for the fragment alone (per-value inspection without reconstruction) |
| `reconstruction_triggered` | `True` if the attack was caught only through reconstruction |
| `trigger_kind`, `trigger_value`, `trigger_raw` | The first candidate classified as an attack |
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
from evilog_fragment_defense import build_default

detector = build_default()                          # gpt-4o-mini security detector
result = detector.detect_fragment("<user input>", session_id="session-123")
if result["aggregated_detected"]:
    memo = result["security_memo"]                  # attach to the masked log
```

Use the same `session_id` for inputs that come from the same session, so that their fragments are
reconstructed together. You can plug in any detector:

```python
from evilog_fragment_defense import FragmentAwareDetector, classify_verdict

detector = FragmentAwareDetector(my_detect_fn, classify_verdict, max_buffer=32)
```

## Reference

[1] D. Pasquini et al., "When AIOps Become 'AI Oops': Subverting LLM-driven IT Operations via
Telemetry Manipulation," USENIX Security Symposium, 2026.
