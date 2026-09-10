# Airlock AI ("AI in the Middle") — build spec

Status: draft, in development. Owner: cyberbobas.
Scope: add two AI features to Airlock, packaged as three install tiers.

Airlock sits at the chokepoint between an AI agent and its tool/MCP calls. That
position is where we put the AI: not batch log upload, but the runtime brain.

## What we are building

**Feature A — Session summary (batch, off the hot path).**
Turn the audit journal of a session into a plain-language narrative: what the
agent did, what was risky, what was blocked. Works with no model at all (a
structured, non-LLM summary); gets a narrative when a model is available.

**Feature B — Inline judge (on the hot path).**
At the decision point for a risky tool/MCP call, decide `allow | block | ask`
with a one-line human reason. Runtime prevention, not post-hoc. This is the moat:
guardrails inspect the prompt; we judge the action.

## The three install tiers (chosen at install, changeable anytime in Settings)

| | Lite | Standard (default) | Pro |
|---|---|---|---|
| Firewall (rules, log, allow/deny/ask) | yes | yes | yes |
| Non-LLM structured summary | yes | yes | yes |
| Built-in mini model (our brain) | no | yes | yes |
| LLM narrative summary | no | yes | yes |
| LLM inline judge (gray-zone) | no | yes | yes |
| Connect a bigger local model / cloud key (BYO) | no | no | yes |
| Offline | 100% | 100% | 100% (mini); cloud only if user turns it on |
| Extra weight | 0 | ~0.5-1 GB (mini) | ~same (adapters are tiny; big models are BYO) |

Rules that keep it non-scary:
1. **Tier is changeable later without reinstall** (download the mini brain to go
   Lite→Standard; enable adapters to go Standard→Pro).
2. **Cloud is OFF by default even in Pro.** Explicit opt-in. Can be hard-locked
   off by org policy (`cloud: locked-off`) so nothing ever leaves the machine.
3. **Standard is pre-selected / recommended.** Most users just click Continue.

## Config additions (`airlock` config file)

New keys (defaults shown), merged into the existing loader, backward-compatible:

```yaml
tier: standard            # lite | standard | pro
ai:
  cloud: off              # off | on | locked-off (policy)
  summary:
    model: builtin-mini   # builtin-mini | <preset/model id> (Pro)
  judge:
    enabled: true         # false in Lite
    model: builtin-mini
    latency_budget_ms: 800  # hard ceiling on the hot path
    on_timeout: ask         # fail-safe: ask | block | allow (allow discouraged)
    on_error:   ask
  provider:               # Pro only; BYO
    preset: ""            # claude | openai | deepseek | qwen | kimi | glm | ollama | custom
    base_url: ""          # filled by preset or custom (OpenAI-compatible)
    model: ""
    # api_key is NOT stored here — see key storage below
```

**Key storage:** API keys live in the OS keychain (macOS Keychain / Windows
Credential Manager / libsecret), never in the plaintext config. (We flag exactly
this anti-pattern in `agentpipe local` LOC-06 and Countersign — we must not do it
ourselves.) Fallback: a 0600 file only if no keychain, with a loud warning.

## AI backend (new module: `airlock/ai/`)

One small interface, pluggable backends. Do NOT write per-vendor integrations.

```
airlock/ai/__init__.py      # get_backend(cfg) -> Backend
airlock/ai/base.py          # Backend protocol: judge(ctx)->Verdict, summarize(events)->str, available()->bool
airlock/ai/builtin.py       # bundled mini model via embedded llama.cpp / llamafile-style runner
airlock/ai/openai_compat.py # base_url + model + key; covers openai/deepseek/qwen/kimi/glm/ollama/vllm/lmstudio
airlock/ai/anthropic.py     # native Claude adapter
airlock/ai/prompts.py       # judge + summary prompt templates, secret redaction
```

`Backend.available()` lets callers degrade gracefully (Lite / no model / cloud
locked-off → returns False → non-LLM path).

Presets = just prefill `base_url` (+ typical model ids); user pastes their key:
claude(anthropic native), openai, deepseek, qwen(dashscope), kimi(moonshot),
glm(zhipu), ollama(localhost:11434/v1), custom. Two adapters cover them all.

## Feature A — session summary

`airlock summary [--session ID] [--json]` (new CLI subcommand).

1. Read the audit journal (see Integration §J) for the session.
2. Compute structured facts with **no model**: counts by tool/verdict, blocked
   actions, secret/FS/network touches, timeline highlights. This alone is the
   Lite output and the always-available fallback.
3. If a model is available, feed the structured facts (not raw secrets) to
   `Backend.summarize()` for a narrative. Redact before sending anywhere.
4. Latency-tolerant (batch). Any model tier is fine.

## Feature B — inline judge (tiered, fail-safe)

Insertion point: right AFTER deterministic policy rules resolve, but only for the
**gray zone** (actions rules mark uncertain / would escalate to a human), and
BEFORE the human prompt (see Integration §D). Pipeline:

1. **Rules / allowlist** decide the vast majority instantly (0 ms) — unchanged.
2. Gray zone only → **mini model** (local, ~50-300 ms, no egress) returns
   `allow|block|ask` + reason.
3. Pro + cloud-on + high-stakes/ambiguous → optionally escalate to the big model
   with a **hard timeout** = `latency_budget_ms`.
4. **Fail-safe:** timeout or error → `on_timeout` / `on_error` (default `ask`).
   The agent must NEVER hang waiting on a model. Dangerous actions fail closed.

Extras: verdict cache (same action → cached), budget cap → fall back to
rules/mini, secret redaction before any model sees the action context.

The judge only ever makes a call SAFER than the rules alone (it can turn an
allow-by-default gray action into ask/block, and can auto-resolve an ask the
human would have seen). It never loosens a hard rule.

## Packaging the mini brain (so install is not "ебалово")

Ship the mini model as a **self-contained runner** (llamafile-style single file,
or embedded llama.cpp) — no Python/CUDA/Ollama for the user. Runs on CPU. Model:
a small (~0.5-1.5B Q4) checkpoint, ideally distilled/fine-tuned by us for the
narrow "is this agent action dangerous?" task, so a tiny model punches above its
weight (our proprietary edge). Delivered inside the Standard/Pro installer, or
fetched once at install from our CDN with a checksum. Never a separate manual
model install.

## Privacy posture (a selling point, not a footnote)

- Default is fully local. Cloud is explicit opt-in and can be locked off.
- Redact secrets before any model call (even local, for logs).
- "Your data never leaves your machine unless you turn on cloud." Put it on the
  page in big letters.

## Build order (milestones)

- **M0 — Foundation.** `tier` + `ai:` config keys + loader; `airlock/ai/base.py`
  interface + a null backend; keychain key storage. No behavior change yet.
- **M1 — Feature A (summary).** Non-LLM structured summary first (Lite, always
  works), then `Backend.summarize()` narrative. Lowest risk, immediate wow.
- **M2 — builtin mini backend.** Embedded runner + model plumbing;
  `Backend.available()` true in Standard/Pro.
- **M3 — Feature B (judge).** Wire the tiered pipeline into the gray-zone seam
  with fail-safe + cache + budget. Feature-flagged, default conservative.
- **M4 — Pro adapters.** openai_compat + anthropic + presets + Settings UI.
- **M5 — Installer chooser.** Three-tier pick; later-switch in Settings.

Ship M0→M1→M2 first (safe, visible). M3 (the moat) after the seam is proven.

## Integration points (mapped from the code)

- **§D decision seam.** `Policy.decide(tool, args) -> Decision` (policy.py). Verdict
  strings `allow | ask | block`; `Decision.combine()` returns the stricter.
  Judge insertion (M3): MCP proxy `_gate_call`, between `posture()` and
  `_resolve()` (mcp_proxy.py ~227→229); hook: cc_hook.py `main` at
  `eff = policy.posture(d).action` (~163). Apply the judge ONLY when
  `d.action != BLOCK`, and it may only raise strictness (allow→ask/block, or
  auto-resolve an ask) — mirroring `apply_flags`/`RANK`. Fail closed if the
  model is unavailable.
- **§H human escalation.** proxy: `ask.resolve_ask(req, ask_fallback, timeout)
  -> (decision, via)`; hook: emits stdout JSON `permissionDecision: ask`. The
  judge runs BEFORE this — an auto-resolved verdict skips the human prompt.
- **§J audit journal.** `audit.audit_path()` → `$AIRLOCK_HOME/audit.jsonl`
  (JSONL, 0600, rotated; read all via `audit.rotated_files()`). Fields:
  ts, event, source, server, tool, decision, effective, reason, resource,
  detail, session, flags, args_digest. **Raw args are NOT stored (only a
  digest)** — so the summary reads no secrets, and redaction of resources is
  belt-and-suspenders. `event="decision"` per gated call; `"outcome"` for ran.
- **§C config.** No separate settings file — config IS the policy YAML. New keys
  `tier`, `ai`, `cloud` added to the `Policy` dataclass + `Policy.load` +
  `validate()`; overlay may only tighten `cloud` (locked-off > off > on).
- **§L CLI.** argparse subparsers; `cmd_<name>(a)->int`, register in
  `build_parser()` with `set_defaults(fn=...)`. `airlock summary` added next to
  `airlock report`. `airlock check` (single dry-run through `decide`) is the
  natural harness for testing the judge (M3) off the hot path.

## Progress

- [x] **M0 — Foundation.** `tier`/`ai`/`cloud` policy keys (+ validate, overlay
      tighten-only for cloud); `airlock/ai/` (`base` Backend/Verdict/JudgeContext,
      NullBackend, `get_backend`, `prompts` with secret redaction). No behavior
      change. Tests: tests/test_ai.py. Full suite green (20/20).
- [x] **M1 — Session summary.** `airlock/summarize.py` (non-LLM structured facts =
      lite output + always-available fallback; `narrate()` uses the backend when
      available). `airlock summary [--days|--all|--session] [--json|--markdown]`.
- [x] **M2 — built-in backend + the training flywheel.** Runtime: **llamafile**
      (single self-contained file, no user install). Model: **Qwen2.5-3B-Instruct
      (Apache-2.0)** — permissive enough to fine-tune and ship our own judge; 7B
      as a heavier profile; swappable. `airlock/ai/openai_compat.py` (one stdlib
      HTTP client for the built-in llamafile AND all BYO/cloud endpoints, with a
      fail-safe verdict parser), `airlock/ai/builtin.py` (lifecycle + `available()`
      by model presence; `AIRLOCK_AI_URL` for a running server). `get_backend`
      selects by tier. **Data flywheel:** `airlock/ai/dataset.py` + `airlock
      ai-dataset` turn human-answered gray-zone decisions into SFT JSONL; `airlock
      ai-status` shows the active tier/model. Fine-tune → GGUF → llamafile recipe
      in `training/`. Tests extended (42 checks); full suite 20/20.
- [x] **M3 — inline judge.** `airlock/ai/judge.py::consult()` wired into both
      enforcement points (mcp_proxy `_gate_call` after `posture`; cc_hook after
      `posture`). Tighten-only (takes the stricter of rules vs judge), never
      touches a hard BLOCK, gray-zone only by default (`ai.judge.check_allow` to
      also scan allows), fail-safe (no model / timeout / off-vocabulary → rules
      decision stands). Opt-in `ai.judge.relax_ask` lets it auto-approve an ask.
      Latency ceiling `ai.judge.latency_budget_ms` (default 800). Proven
      end-to-end through the proxy (allow→block in standard, no-op in lite).
      Tests: 52 checks in tests/test_ai.py; full suite 20/20.
- [x] **M4 — Pro adapters (bring your own model).** Native Anthropic adapter
      (`anthropic.py`); provider presets (`providers.py`: claude, openai, deepseek,
      qwen, kimi, glm, ollama, custom) that just prefill base_url+model; API keys
      in the OS keychain with a 0600 fallback (`keys.py`) — never in the policy
      file. `get_backend` (pro): a configured BYO model wins, else the built-in.
      **Cloud gating enforced in `backend_for`:** a cloud preset is refused unless
      `cloud: on`, a key is required for cloud, local presets always allowed.
      CLI `airlock ai-key` (keychain) + `airlock ai-provider <preset>` (one
      command to point pro at your own model); `ai-status` shows provider + key.
      Judge latency budget auto-scales (local ~800ms hot path, cloud ~6000ms so a
      cloud judge actually runs; `ai.judge.latency_budget_ms` overrides).
      **Live-validated** against real models: Ollama (local), DeepSeek (cloud),
      and Claude (via OpenAI-compatible endpoint) — each blocks `curl|sh`, allows a
      benign read, and summarizes, through the real pipeline. Tests: 80 checks;
      full suite 20/20.
- [x] **M5 — tier chooser + in-Settings switch + model install.** `airlock init`
      picks the tier (`--tier`, `$AIRLOCK_TIER`, or an interactive 1/2/3 prompt,
      default standard) and writes it into the policy it creates; `install.sh`
      surfaces it. `airlock ai-tier [lite|standard|pro]` switches later without a
      reinstall (line-edits the policy, preserving the rest, re-validates).
      `airlock ai-model --path|--url` installs the llamafile into
      `~/.airlock/models/`. Tests: 71 checks; full suite 20/20.

**Off-box (handed to the GPU machine):** `training/TASK-gpu-box.md` — a
dummy-proof Claude Code runbook to harvest data → QLoRA fine-tune → GGUF →
llamafile → evaluate (ship gate: false-allow-on-must-block = 0) → deliver
`airlock-judge-v1.llamafile`. Plus `training/eval_judge.py`.
