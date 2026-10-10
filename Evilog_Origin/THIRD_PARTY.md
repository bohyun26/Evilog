# Third-party components

This artifact depends on two components from the base paper's ecosystem
(*When AIOps Become "AI Oops"*, Pasquini et al., USENIX Security 2026).

## AIOpsShield — NOT bundled (fetch it yourself)

The experiments import the released **AIOpsShield** defense (`from aiopsshield ...`).
At the time of writing, the released code **does not include a LICENSE file**, so we treat it
as "all rights reserved" and **do not redistribute it** here.

To run the artifact:

1. Obtain AIOpsShield from the base paper's official release/artifact.
2. Place it so that `AIOpsShield/aiopsshield/` sits at this artifact's root, **or** set
   `export AIOPSSHIELD_PATH=/abs/path/to/AIOpsShield`.

We do **not** modify AIOpsShield's source. The only adaptation is a **runtime monkeypatch** in
`harness/live_anchor.py` that swaps RegexMaker's `AzureOpenAI` client for the standard `OpenAI`
client, so the template-derivation step can use an OpenAI key instead of Azure. The defense's
logic, prompts, and feedback loop are untouched.

## demo_target — bundled (Apache License 2.0)

`demo_target/` is derived from **AIOpsDoom** (Apache-2.0). It is redistributable with attribution,
so it is bundled here together with its `LICENSE` and `COPYRIGHT`. Apache-2.0 requires stating
changes: our modifications are documented in `demo_target/MODIFICATIONS.md`.
