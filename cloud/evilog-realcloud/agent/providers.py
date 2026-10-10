#!/usr/bin/env python3
"""
agent/providers.py - one chat interface across OpenAI, Google and Anthropic.

WHY
---
The RCA agent has to behave identically across vendors or the cross-vendor
comparison measures SDK differences instead of defence differences. So the agent
loop stays in rca_agent.py and only the transport lives here: same system prompt,
same tool definition, same temperature, same round budget, whichever vendor answers.

MESSAGE FORMAT (vendor-neutral; converted per call, never stored natively)
--------------------------------------------------------------------------
  {"role": "system",    "content": str}
  {"role": "user",      "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","args"}]}
  {"role": "tool",      "tool_call_id": str, "name": str, "content": str}

TOOL FORMAT
-----------
  [{"name": str, "description": str, "parameters": <JSON schema>}]

chat() returns {"text": str, "tool_calls": [{"id","name","args"}]}.

MODEL ROUTING is by prefix: gpt-/o1/o3/o4 -> OpenAI, gemini- -> Google,
claude- -> Anthropic.

KEYS come from the environment: OPENAI_API_KEY, GOOGLE_API_KEY (or
GEMINI_API_KEY), ANTHROPIC_API_KEY.

INSTALL
-------
  pip install openai anthropic google-genai --break-system-packages

SMOKE TEST (do this before spending a long run)
-----------------------------------------------
  py -3.12 agent\\providers.py --check gpt-4o-2024-08-06 gemini-3.6-flash claude-sonnet-5

It asks each model to call a dummy tool. A model that answers without calling the
tool would, in the real experiment, be answering without reading the logs - which
is why the check reports tool use explicitly rather than just "it responded".
"""

import json
import os
import sys

_clients = {}

# Models that reject an explicit temperature. Discovered at runtime on the first
# 400 and cached, so a long multi-vendor run does not die on its first Claude call.
# Recorded rather than hidden: a model whose sampling we cannot pin to 0 is less
# deterministic than the others, and the paper should say so.
_NO_TEMPERATURE = set()


def temperature_pinned(model):
    """False once a model has been observed to reject temperature=0."""
    return model not in _NO_TEMPERATURE


def _is_temperature_error(exc):
    s = str(exc).lower()
    return "temperature" in s and ("deprecated" in s or "unsupported" in s
                                   or "not supported" in s or "does not support" in s)


# Reasoning-style models spend part of the completion budget before emitting any
# text. At 600 tokens a verbose model can return an EMPTY answer, which grades as
# "saw nothing" and silently looks like a defence result. Give each vendor room.
DEFAULT_MAX_TOKENS = {"openai": 900, "google": 900, "anthropic": 16000}

# Models that reject an explicit thinking parameter. Extended thinking is disabled
# where possible: the other vendors answer without a reasoning phase, so leaving it
# on would compare "model that reasons first" against "model that does not" instead
# of comparing defences. Where it cannot be turned off, the budget absorbs it.
_NO_THINKING_PARAM = set()


def provider_for(model):
    m = str(model).lower()
    if m.startswith(("gpt-", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    if m.startswith("gemini"):
        return "google"
    if m.startswith("claude"):
        return "anthropic"
    raise ValueError(f"cannot route model {model!r} to a provider - "
                     f"expected a gpt-*, gemini-* or claude-* name")


# ---------------------------------------------------------------- OpenAI

def _openai(model, messages, tools, temperature, max_tokens):
    from openai import OpenAI
    client = _clients.get("openai") or _clients.setdefault("openai", OpenAI())

    msgs = []
    for m in messages:
        if m["role"] == "assistant":
            e = {"role": "assistant", "content": m.get("content") or ""}
            if m.get("tool_calls"):
                e["tool_calls"] = [{"id": tc["id"], "type": "function",
                                    "function": {"name": tc["name"],
                                                 "arguments": json.dumps(tc["args"])}}
                                   for tc in m["tool_calls"]]
            msgs.append(e)
        elif m["role"] == "tool":
            msgs.append({"role": "tool", "tool_call_id": m["tool_call_id"],
                         "content": m["content"]})
        else:
            msgs.append({"role": m["role"], "content": m["content"]})

    # reasoning models reject an explicit temperature
    base = dict(model=model, messages=msgs,
                tools=[{"type": "function", "function": t} for t in tools],
                tool_choice="auto", max_completion_tokens=max_tokens)
    pin = (not str(model).startswith(("o1", "o3", "o4", "gpt-5"))
           and model not in _NO_TEMPERATURE)
    try:
        r = client.chat.completions.create(**({"temperature": temperature} if pin else {}),
                                           **base)
    except Exception as e:
        if not (pin and _is_temperature_error(e)):
            raise
        _NO_TEMPERATURE.add(model)
        print(f"[providers] {model} rejects temperature; "
              f"running at its default sampling (report this)")
        r = client.chat.completions.create(**base)

    msg = r.choices[0].message
    calls = []
    for tc in (msg.tool_calls or []):
        try:
            args = json.loads(tc.function.arguments or "{}")
        except ValueError:
            args = {}
        calls.append({"id": tc.id, "name": tc.function.name, "args": args})
    return {"text": msg.content or "", "tool_calls": calls,
            "stop_reason": r.choices[0].finish_reason}


# ---------------------------------------------------------------- Anthropic

def _anthropic(model, messages, tools, temperature, max_tokens):
    import anthropic
    client = _clients.get("anthropic") or _clients.setdefault("anthropic", anthropic.Anthropic())

    system = "\n".join(m["content"] for m in messages if m["role"] == "system")
    conv = []
    for m in messages:
        if m["role"] == "system":
            continue
        if m["role"] == "user":
            conv.append({"role": "user", "content": m["content"]})
        elif m["role"] == "assistant":
            blocks = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in (m.get("tool_calls") or []):
                blocks.append({"type": "tool_use", "id": tc["id"],
                               "name": tc["name"], "input": tc["args"]})
            conv.append({"role": "assistant",
                         "content": blocks or [{"type": "text", "text": "(no content)"}]})
        elif m["role"] == "tool":
            block = {"type": "tool_result", "tool_use_id": m["tool_call_id"],
                     "content": m["content"]}
            # consecutive tool results belong in one user turn
            if conv and conv[-1]["role"] == "user" and isinstance(conv[-1]["content"], list):
                conv[-1]["content"].append(block)
            else:
                conv.append({"role": "user", "content": [block]})

    kw = dict(model=model, system=system, messages=conv,
              tools=[{"name": t["name"], "description": t["description"],
                      "input_schema": t["parameters"]} for t in tools],
              max_tokens=max_tokens)

    def _call(**over):
        call_kw = dict(kw, **over)
        if model not in _NO_TEMPERATURE:
            call_kw["temperature"] = temperature
        if model not in _NO_THINKING_PARAM:
            call_kw["thinking"] = {"type": "disabled"}
        while True:
            try:
                return client.messages.create(**call_kw)
            except Exception as exc:
                if "thinking" in call_kw and "thinking" in str(exc).lower():
                    _NO_THINKING_PARAM.add(model)
                    call_kw.pop("thinking")
                    print(f"[providers] {model} will not disable thinking; "
                          f"it reasons before answering (report this)")
                    continue
                if "temperature" in call_kw and _is_temperature_error(exc):
                    _NO_TEMPERATURE.add(model)
                    call_kw.pop("temperature")
                    print(f"[providers] {model} rejects temperature; "
                          f"running at its default sampling (report this)")
                    continue
                raise

    r = _call()

    # A reasoning phase can eat the whole budget and leave no answer at all. That
    # grades as "the agent saw nothing", which is indistinguishable from a defence
    # having blinded it - so retry once with room rather than record a false zero.
    def _empty(resp):
        return not "".join(b.text for b in resp.content
                           if getattr(b, "type", "") == "text").strip()

    if getattr(r, "stop_reason", None) == "max_tokens":
        bigger = max_tokens * 4
        why = "produced no answer" if _empty(r) else "was cut off mid-answer"
        print(f"[providers] {model} {why} within {max_tokens} tokens; retrying at {bigger}")
        r = _call(max_tokens=bigger)
        if getattr(r, "stop_reason", None) == "max_tokens":
            think = sum(1 for b in r.content
                        if getattr(b, "type", "") in ("thinking", "redacted_thinking"))
            print(f"[providers] {model} still truncated at {bigger} tokens "
                  f"(thinking blocks in response: {think}) - raise "
                  f"DEFAULT_MAX_TOKENS['anthropic'] further")

    text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    calls = [{"id": b.id, "name": b.name, "args": dict(b.input or {})}
             for b in r.content if getattr(b, "type", "") == "tool_use"]
    thinking = sum(1 for b in r.content
                   if getattr(b, "type", "") in ("thinking", "redacted_thinking"))
    return {"text": text, "tool_calls": calls, "thinking_blocks": thinking,
            "stop_reason": getattr(r, "stop_reason", None)}


# ---------------------------------------------------------------- Google

def _google(model, messages, tools, temperature, max_tokens):
    from google import genai
    from google.genai import types

    if "google" not in _clients:
        key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        _clients["google"] = genai.Client(api_key=key) if key else genai.Client()
    client = _clients["google"]

    system = "\n".join(m["content"] for m in messages if m["role"] == "system")
    contents = []
    for m in messages:
        if m["role"] == "system":
            continue
        if m["role"] == "user":
            contents.append(types.Content(role="user",
                                          parts=[types.Part(text=m["content"])]))
        elif m["role"] == "assistant":
            # Gemini 3 attaches a thought signature to each function call and rejects
            # the next turn if it is not echoed back verbatim. Rebuilding the Content
            # from our neutral format drops it, so replay the model's own object when
            # we still have it. This is why a one-turn smoke test passed while every
            # real (two-turn) run failed with a ClientError.
            if m.get("native") is not None:
                contents.append(m["native"])
                continue
            parts = []
            if m.get("content"):
                parts.append(types.Part(text=m["content"]))
            for tc in (m.get("tool_calls") or []):
                parts.append(types.Part(function_call=types.FunctionCall(
                    name=tc["name"], args=tc["args"])))
            contents.append(types.Content(role="model",
                                          parts=parts or [types.Part(text="(no content)")]))
        elif m["role"] == "tool":
            # Gemini matches tool results by NAME, not by call id
            part = types.Part(function_response=types.FunctionResponse(
                name=m.get("name") or "get_logs", response={"result": m["content"]}))
            if contents and contents[-1].role == "user":
                contents[-1].parts.append(part)
            else:
                contents.append(types.Content(role="user", parts=[part]))

    decls = [types.FunctionDeclaration(name=t["name"], description=t["description"],
                                       parameters=t["parameters"]) for t in tools]
    cfg = types.GenerateContentConfig(
        system_instruction=system or None, temperature=temperature,
        max_output_tokens=max_tokens,
        tools=[types.Tool(function_declarations=decls)])

    r = client.models.generate_content(model=model, contents=contents, config=cfg)

    text, calls, native = "", [], None
    for cand in (r.candidates or []):
        if native is None:
            native = getattr(cand, "content", None)
        for p in (getattr(cand.content, "parts", None) or []):
            if getattr(p, "text", None):
                text += p.text
            fc = getattr(p, "function_call", None)
            if fc:
                calls.append({"id": f"gemini-call-{len(calls)}", "name": fc.name,
                              "args": dict(fc.args or {})})
    stop = None
    if r.candidates:
        stop = getattr(r.candidates[0], "finish_reason", None)
    return {"text": text, "tool_calls": calls, "native": native,
            "stop_reason": str(stop) if stop else None}


# ---------------------------------------------------------------- entry point

_BACKENDS = {"openai": _openai, "anthropic": _anthropic, "google": _google}


def chat(model, messages, tools, temperature=0.0, max_tokens=None):
    """Send one turn to whichever vendor owns `model`."""
    prov = provider_for(model)
    if max_tokens is None:
        max_tokens = DEFAULT_MAX_TOKENS[prov]
    return _BACKENDS[prov](model, messages, tools, temperature, max_tokens)


# ---------------------------------------------------------------- smoke test

def _check(models):
    tools = [{"name": "get_logs",
              "description": "Return the most recent application log lines.",
              "parameters": {"type": "object",
                             "properties": {"limit": {"type": "integer",
                                                      "description": "how many recent lines"}}}}]
    msgs = [{"role": "system", "content": "You are an AIOps agent. Use tools to investigate."},
            {"role": "user", "content": "Something is wrong with logins. Check the logs first."}]

    fake_logs = ('{"ts":"2026-08-09T19:36:09Z","event":"config.reload",'
                 '"key":"feed_page_size","old":10,"new":200}\n'
                 '{"ts":"2026-08-09T19:36:20Z","event":"auth.login_failed",'
                 '"attempted_username":"admin\' OR \'1\'=\'1\' --"}')

    worst = 0
    for model in models:
        try:
            r1 = chat(model, msgs, tools)
            names = [c["name"] for c in r1["tool_calls"]]
            if not names:
                print(f"  WARN  {model:28} answered WITHOUT calling the tool - "
                      f"it would never read the logs: {r1['text'][:70]!r}")
                worst = max(worst, 1)
                continue

            # Turn 2 is the one that matters: the experiment always feeds a tool
            # result back. A one-turn check passes on adapters that still break here.
            turn2 = msgs + [
                {"role": "assistant", "content": r1["text"],
                 "tool_calls": r1["tool_calls"], "native": r1.get("native")},
                {"role": "tool", "tool_call_id": r1["tool_calls"][0]["id"],
                 "name": r1["tool_calls"][0]["name"], "content": fake_logs},
            ]
            r2 = chat(model, turn2, tools)
            temp = "temp=0" if temperature_pinned(model) else "temp=DEFAULT"
            if r2["text"].strip():
                print(f"  OK    {model:28} tool={names[0]} args={r1['tool_calls'][0]['args']} "
                      f" {temp}  answered {len(r2['text'])} chars "
                      f"(stop={r2.get('stop_reason')})")
            elif r2["tool_calls"]:
                # Asking for more logs instead of concluding is normal agent
                # behaviour, not a failure - the real loop keeps going for
                # MAX_ROUNDS. Only an empty turn with no tool call is broken.
                print(f"  OK    {model:28} tool={names[0]} args={r1['tool_calls'][0]['args']} "
                      f" {temp}  investigated further: called "
                      f"{[c['name'] for c in r2['tool_calls']]} "
                      f"args={r2['tool_calls'][0]['args']} (multi-round agent)")
            else:
                print(f"  WARN  {model:28} second turn returned NO TEXT and NO TOOL CALL "
                      f"(stop={r2.get('stop_reason')}) - would grade as 'saw nothing'")
                worst = max(worst, 1)
        except Exception as e:
            print(f"  FAIL  {model:28} {type(e).__name__}: {str(e)[:400]}")
            worst = 2
    return worst


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
        print("provider smoke test")
        print("-" * 70)
        sys.exit(_check(sys.argv[2:]))
    print(__doc__)
