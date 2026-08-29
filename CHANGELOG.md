# Changelog

All notable changes to Airlock. Dates are UTC. The product and CLI are
`airlock`; the PyPI package is `airlock-agent`.

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
