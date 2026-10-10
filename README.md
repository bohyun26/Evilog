# Evilog
Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents

LLM-based AIOps agents diagnose incidents by analyzing logs that contain user-controlled input. To block prompt injection through that input, a prior defense (AIOpsShield) masks all user-controlled fields before the agent reads them. However, in application-layer attacks (e.g., SQL injection, XSS, Log4Shell), the user input itself is the key evidence of the attack — so masking blocks the injection but, as a side effect, conceals the attack from the agent.

We evaluate attack detection, diagnostic accuracy, and prompt-injection blocking while varying the sanitization method, the attack type, the model, and the environment (local Flask and AWS EKS). For prompt injection, masking works as intended: all three models block the attack in all 20 trials. For application-layer attacks, however, the same masking hides evidence the agent would otherwise use.

To address this, we propose Evilog, which detects attack evidence before AIOpsShield’s masking and preserves it as security metadata. Evilog maintains full prompt-injection blocking while additionally detecting application-layer attacks in all 20 trials.
