# Changelog

All notable changes to Airlock. Dates are UTC. The product and CLI are
`airlock`; the PyPI package is `airlock-agent`.

## [Unreleased]

Start of the AI layer ("AI in the Middle") — see `docs/AI-SPEC.md`. Three tiers
(lite / standard / pro); the AI is optional, only ever tightens a decision, and
fails closed when unavailable, so the fail-closed core invariant is preserved.

### Added
- **`airlock summary`** — a plain-language recap of a session from the audit log:
  decisions, what was blocked/asked, scan flags, top tools and targets. Works
  with no model at all (structured, non-LLM output = the `lite` tier); a
  narrative is added when an AI backend is available. Flags:
  `--days | --all | --session | --json | --markdown`. New module
  `airlock/summarize.py`.
- **`airlock/ai/`** — the optional runtime brain. One small `Backend` interface
  (`available` / `judge` / `summarize`), a `NullBackend` fallback, `Verdict`
  (out-of-vocabulary → `ask`, marked failsafe), `JudgeContext`, and secret
  redaction applied before anything reaches a model.
- **Policy keys `tier`, `ai`, `cloud`** (backward-compatible; unknown-value =
  loud load error, not a silent half-load). A repo overlay may only *tighten*
  `cloud` egress (`locked-off` > `off` > `on`), never open it.

- **Built-in AI backend (standard/pro tiers).** Runs our own model locally as a
  **llamafile** (one self-contained file — no Ollama/CUDA/Python for the user).
  Default model **Qwen2.5-3B-Instruct** (Apache-2.0), swappable. `airlock/ai/
  openai_compat.py` is one stdlib HTTP client shared by the built-in model and
  every OpenAI-compatible local/cloud endpoint, with a fail-safe verdict parser
  (unparseable → no opinion, never a silent allow). `get_backend` selects by tier
  and degrades to the non-AI path when no model is installed.
- **`airlock ai-status`** — shows the active tier, cloud setting, and whether a
  model is installed / the backend is available.
- **`airlock ai-dataset`** — the training flywheel: exports human-answered
  gray-zone decisions from the audit log as chat-format SFT JSONL (redacted,
  human-answers-only by default) to fine-tune our judge. Recipe in `training/`
  (QLoRA → merge → GGUF → llamafile).

- **Inline AI judge** (the moat) — `airlock/ai/judge.py`, wired into both
  enforcement points (MCP proxy and the Claude Code hook) right after the rules
  resolve. It only ever makes a call *safer*: it takes the stricter of the rules'
  and the model's verdict, **never lifts a hard block**, and by default runs only
  on the gray zone the rules escalated (`ask`) — not on every allow. It **fails
  closed**: no model, a timeout past `ai.judge.latency_budget_ms` (default 800ms),
  or an off-vocabulary reply all leave the rules' decision untouched. Opt-in
  `ai.judge.check_allow` also scans allows; opt-in `ai.judge.relax_ask` lets it
  auto-approve an ask. No-op in the `lite` tier or with no model installed.

- **Pro tier: bring your own model.** A native Anthropic (Claude) adapter plus
  provider presets (`claude`, `openai`, `deepseek`, `qwen`, `kimi`, `glm`,
  `ollama`, `custom`) that only prefill base_url + model — one OpenAI-compatible
  client and one Anthropic client cover them all. API keys are stored in the OS
  **keychain** (0600-file fallback with a loud warning), never in the policy file.
  **Cloud egress is gated:** a cloud provider is refused unless `cloud: on`, needs
  a key, and `locked-off` can never be opened; local providers (Ollama / a
  localhost endpoint) always work. `airlock ai-key --provider … [--delete|--show]`
  manages keys; `airlock ai-provider <preset> [--model --base-url --cloud]` points
  the pro tier at your own model in one command; `airlock ai-status` shows it. The
  judge's latency budget scales with model location (short for a local model on
  the hot path, longer for cloud so a cloud judge actually runs;
  `ai.judge.latency_budget_ms` overrides).
- **Live-validated** against real models end-to-end: a local model via **Ollama**,
  **DeepSeek** (cloud), and **Claude** (via an OpenAI-compatible endpoint) — each
  blocks a `curl | sh`, allows a benign read, and writes a session summary through
  the real judge pipeline (fail-safe and the cloud budget included).

- **Install-time tier chooser + in-Settings switch.** `airlock init` now picks
  the AI tier (`--tier`, `$AIRLOCK_TIER`, or an interactive prompt; default
  standard) and writes it into the policy; the installer surfaces it. `airlock
  ai-tier [lite|standard|pro]` switches tiers later with no reinstall (edits the
  policy in place and re-validates). `airlock ai-model --path|--url` installs the
  built-in llamafile into `~/.airlock/models/`.
- **Off-box training kit** (`training/`): `TASK-gpu-box.md` (a step-by-step
  Claude Code runbook for a GPU machine), `finetune_qlora.py` (16GB-friendly),
  `build_llamafile.sh`, and `eval_judge.py` with a hard ship gate
  (false-allow-on-must-block = 0).

### Changed
- **`airlock --help` is now a real menu.** Commands are grouped and explained
  (first run · every day · AI in the middle · policy & admission · evidence &
  upkeep) instead of one flat alphabetical dump, with a dedicated AI section that
  names the tiers and states the safety model (the AI only ever tightens; cloud
  off by default). Bare `airlock` prints the menu instead of a terse error.

### Testing
- `tests/test_ai.py` (75 checks): config keys + validation, backend fail-safe,
  redaction, non-LLM summary, verdict parsing, the built-in backend over a stub
  endpoint, dataset harvesting, and the inline judge (tighten-only, hard-block
  untouched, gray-zone default, opt-in relax, fail-safe). An end-to-end proxy run
  confirms the judge tightens allow→block in `standard` and is a no-op in `lite`.
  Full suite 20/20.

## [0.5.3] — 2026-08-29

Additional adversarial testing of `breach` and one more fix.

### Fixed
- `breach`: URL host extraction no longer swallows a backslash, query string or
  fragment (`https://host\path`, `https://host/p?x=1#f` now resolve to `host`).
  Found during extended edge-case testing; regression-tested.

### Testing
- Extended `test_breach.py` to **37 checks**: URL-host edges, exact window
  boundary (inclusive at `--window`, exclusive one second past), egress-before-
  read never attributed, SSRF/metadata egress correlation.

## [0.5.2] — 2026-08-29

Fixes from an adversarial deep-test pass on `breach` (8 of 9 findings; the 9th
is a documented scaling limit).

### Fixed
- **CRITICAL — timezone.** `breach` on a live log parsed UTC timestamps with
  local `mktime`, so off-UTC machines silently dropped or misplaced records and
  could report **"clean" on a log that held an incident**. Now parsed as UTC
  with `calendar.timegm`; `--since`/`--until` are UTC too. (The earlier 0.5.1
  fix only covered the in-memory/`--simulate` path.) Verified identical across
  UTC / LA / Tokyo / Moscow / UTC+14, with a timezone-invariance regression test.
- **Concurrent rotation TOCTOU.** `airlock verify` (and therefore `breach`)
  tracebacked with `FileNotFoundError` when log rotation renamed a segment
  mid-read while an agent was writing. Now skipped safely — the ledger still
  catches a segment that truly vanished. (Shared with `airlock verify`.)
- **Windows credential paths.** `C:\Users\…\.aws\credentials` and similar were
  not classified; backslashes are now normalized before matching.
- `breach`: a search tool's query text no longer fabricates a phantom egress
  (`WebSearch` excluded; a non-shell egress must *start* with the host, not
  merely mention one).
- `breach`: `.env.sample` / `.env.example` / `*.dist` / `*.template` are treated
  as placeholders, not secrets (`.env.local` is still a secret).
- `breach`: `--report FILE` now always writes the artifact (previously silent
  unless `--markdown` was also passed); `--json --report` writes JSON.
- `breach`: repeated reads of the same secret collapse to one burn / one
  checklist item.
- `breach`: report fields are rendered through `audit.safe()`, so an ANSI/newline
  payload inside a path can no longer forge a report line.
- `breach`: an unparseable `--since`/`--until` now warns instead of silently
  meaning "all history"; a wildly large relative value no longer tracebacks.

### Known limits
- `breach` loads the whole log into memory to sort (peak RSS a few times the log
  size). Fine for a workstation; a multi-million-record history wants a streaming
  per-segment merge. Tracked, not a correctness issue.

## [0.5.1] — 2026-08-27

### Fixed
- `breach --simulate` and in-memory scenarios were filtered against the wall
  clock, so a scenario timestamped later in the day than "now" was dropped and
  the result depended on the machine timezone. In-memory scenarios now use an
  open upper bound.

## [0.5.0] — 2026-08-27

### Added
- **`airlock breach` — post-compromise reconstruction.** A read-only command
  that answers, from the audit log you already have: what did the agent touch,
  did any of it leave the machine, and which exact credentials to rotate.
  - Reconstructs secret-read → egress flows across rotated segments.
  - Opens with an integrity banner — runs `verify` across every segment first,
    so the report proves the log it reasoned over was not edited or truncated.
  - Grades evidence honestly: `CONFIRMED` only on payload-digest linkage; a
    known-collector hit is `PROBABLE` (exfiltration happened, attribution
    unproven); a read with no correlated egress is `POSSIBLE`. Time-proximity
    alone is never `CONFIRMED`.
  - Surfaces gate-config changes and model-API egress ("leaked to model
    context") as their own categories; the latter is never counted as exfil.
  - States coverage every report; a clean window rotates nothing and says so.
  - `--simulate`, `--json`, `--markdown`, `--report FILE`, `--since/--until/`
    `--session/--window`. Exit codes for IR scripts: `0` clean, `1` burns, `2`
    log untrustworthy.
  - Classification is derived at read time from existing fields, so it works on
    logs that predate the feature with zero hot-path changes.

## [0.4.8] — 2026-08-27

### Fixed
- Non-atomic policy write race: `write_atomic()` and `grants.add()` shared a
  fixed `<name>.tmp`, so two concurrent `airlock allow` processes could publish a
  zero-byte policy for an instant. Each write now uses a unique temp file.
- `airlock --version` no longer drifts from `pyproject` — it is read from the
  installed package metadata.

## [0.4.7] — 2026-08-27

### Added
- **Headless fail-closed option.** On a headless host (VM / CI / server) where
  `guard` would let an unanswered `ask` resolve to *allow*, set `unattended:
  block` in the policy or `AIRLOCK_UNATTENDED=block` to fail closed. `airlock
  doctor` reports the resolved posture (ok when it fails closed, warn with a fix
  hint when it fails open).

## [0.4.6] and earlier

Runtime firewall for AI coding agents: MCP stdio proxy + Claude Code PreToolUse
hook, one policy engine (observe / guard / enforce), hash-chained tamper-evident
audit, TOFU toolset pinning (rug-pull detection), static scan of tool
descriptions, per-skill contracts, `init`/`doctor`/`uninstall` across Claude
Code, Cursor, Windsurf, Cline, Claude Desktop, Kimi, grok, mimo and DeepSeek.
