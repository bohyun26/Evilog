# Evilog: Fragment-Aware Detection

This directory contains the fragment-aware attack detection component of **Evilog** (*Evidence-Preserving Log Sanitization for LLM-based AIOps Agents*). It supports the experiment described in **Section V-E-1 (Fragment Attack)** of the paper.

[← Back to the main README](../../README.md)

## Overview

Evilog uses a **detect-then-mask** approach: it checks user-controlled log values for application-layer attack evidence before AIOpsShield masks them. When an attack is identified, Evilog masks the original input and retains its type in a security memo (e.g., `SECURITY: SQLi detected`) for downstream diagnosis.

Fragmentation presents a challenge because an attack payload may be submitted as multiple separate inputs. Individual fragments may appear benign even though their ordered combination contains a recognizable attack. The fragment-aware component maintains a **per-session buffer**, reconstructs the input, and checks the reconstructed candidate before sanitization.

## Detection Workflow

```text
User-controlled input fragment
           |
           v
Append to the session buffer (max. 32 values)
           |
           v
Build candidates: individual fragment + ordered reconstruction
           |
           v
LLM-based security detector (GPT-4o-mini)
           |
      Attack found?
       /       \
     Yes        No
      |          |
Generate security  No security memo
memo with type      |
       \         /
        v       v
      AIOpsShield masking
               |
               v
      Sanitized log -> AIOps agent
```

**Implementation details**

- **Buffer:** Up to 32 input values per session; inputs are reconstructed in arrival order.
- **Detector:** The underlying Evilog security detector and its constrained verdict format are reused rather than retrained.
- **Default reconstruction:** `"".join(...)`, preserving the order and literal content of the received fragments without inserting separators.
- **Optional configuration:** `window_sizes` can limit reconstruction to recent fragments; `join_variants` can add separators such as spaces or newlines. These options may change detection behavior and false-positive risk and are not claimed as independently validated in the paper.
- **Session scope:** Use a consistent `session_id` for fragments from one session; reset buffers between independent test cases to avoid cross-case contamination.

Reconstructing benign fragments is **not**, by itself, a guarantee against false positives. Detection accuracy depends on the detector and the way inputs are grouped into sessions.

## Experimental Setup (Paper, Section V-E-1)

The robustness evaluation used **seven application-layer attacks** and **five fragmentation schemes**, for **35 attack–fragmentation combinations**.

| Setting | Configuration |
|---|---|
| Attack types | SQL injection, command injection, XSS, Log4Shell, NoSQL injection, LDAP injection, SSTI |
| Injection fields | Login-identifier field for the attacks other than Log4Shell; HTTP `Referer` for Log4Shell |
| Fragmentation | Token, whitespace, operator, fixed-length, random |
| Buffer limit | 32 values per session |
| Security detector | GPT-4o-mini in the evaluated Evilog implementation |

**Fragmentation schemes:**

- **Token:** Split at token boundaries.
- **Whitespace:** Split according to whitespace boundaries.
- **Operator:** Split around operators in the payload.
- **Fixed-length:** Divide into fragments of a fixed number of characters.
- **Random-length:** Divide into fragments whose lengths are randomly determined.

For each combination, input fragments are submitted in sequence under the same session identifier. This lets the detector evaluate both the individual fragment and the reconstructed sequence.

## Experimental Results

| Defense condition | Detected combinations | Detection rate |
|---|---:|---:|
| No Defense | 32 / 35 | 91.4% |
| AIOpsShield | Attack evidence masked; attack type not identified in the evaluated fragmented cases | — |
| **Evilog (fragment-aware)** | **35 / 35** | **100%** |

Under No Defense, detection failed for **token-fragmented NoSQL injection, LDAP injection, and SSTI**. Evilog identified these cases after reconstructing fragments from the same session. In the LDAP injection example, **all 14 individual fragments were classified as benign**, yet the reconstructed input was detected as LDAP injection.

The **35/35** result applies to the reported attack types and fragmentation strategies; it does not establish universal detection of unseen fragmentation patterns or attacks.

**Processing overhead:** Maintaining the buffer and checking reconstructed candidates adds detector calls and computational cost. Under the documented default approach, checking an individual fragment and one reconstruction can require up to **two detector calls per input**; this is a description of the component's expected call pattern, not a separate measured latency result. For the paper's measured overall sanitization overhead, see [Latency Evaluation](../Latency%20Measurement/LATENCY_EVALUATION.md).

## Implementation Reference

The following interface names are described for `evilog_fragment_defense.py`. Check the actual Python file and its location in the repository before treating the examples as executable reproduction instructions.

| Name | Purpose |
|---|---|
| `DETECTOR_SYSTEM_PROMPT` | Detector instructions and supported attack taxonomy |
| `classify_verdict(verdict)` | Map raw detector output to `benign`, `instruction`, or `attack` |
| `security_memo(verdict)` | Format the memo `SECURITY: <type> detected` |
| `SecurityDetector` | LLM-based detector; default model `gpt-4o-mini` |
| `FragmentAwareDetector` | Buffer and reconstruction wrapper around a detector |
| `build_default(model, **kw)` | Create a fragment-aware detector using the default security detector |

### Key parameters

| Parameter | Default | Meaning |
|---|---|---|
| `detect_fn` | Required | Function or callable returning a raw detector verdict |
| `classify_fn` | `classify_verdict` | Normalize detector output |
| `window_sizes` | `None` | Optionally restrict reconstruction to recent fragments |
| `join_variants` | `("",)` | Strings used to join fragments; default concatenates without separators |
| `max_buffer` | `32` | Maximum number of stored values per session |

**Key methods:** `detect_fragment(fragment, session_id)` adds a fragment and evaluates candidates; `reset(session_id=None)` clears one buffer, or all buffers if no session is specified.

The `detect_fragment` result provides `aggregated_detected` and `security_memo`, along with diagnostic information such as `fragment_bucket`, `reconstruction_triggered`, `detector_calls`, and `candidates_checked`. Additional returned fields depend on the implementation.

## Usage

Requirements stated for the component: **Python 3.9+** and the `openai` package.

```bash
pip install openai
```

Set `OPENAI_API_KEY` in your environment using your shell's environment-variable mechanism; do not commit credentials to GitHub.

When running a script from the directory containing `evilog_fragment_defense.py`, the intended Python interface is:

```python
from evilog_fragment_defense import build_default

detector = build_default()
result = detector.detect_fragment("<user input>", session_id="session-123")

if result["aggregated_detected"]:
    memo = result["security_memo"]
    # Attach the security memo to the sanitized log.

# Reset the buffer between independent cases, where appropriate.
detector.reset("session-123")
```

Fragments belonging to the same session must use the same `session_id`. The sample above illustrates the Python API; it is **not** a complete end-to-end AIOpsShield/Flask experiment command. Full reproduction also requires the relevant application/logging pipeline and detector credentials.

## References

[1] D. Pasquini et al., “When AIOps Become ‘AI Oops’: Subverting LLM-driven IT Operations via Telemetry Manipulation,” *USENIX Security Symposium*, 2026.

For the core evidence-preserving sanitization design and broader experimental evaluation, see the [main Evilog README](../../README.md).
