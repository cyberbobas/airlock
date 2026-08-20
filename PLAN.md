# Airlock MVP — scope and status

**Thesis:** build the narrowest thing that gives a viral demo *and* a real moat.
That is the enforcement spine on planes **④ (skill admission)** + **② (action)**.
Everything else — semantic review, sandbox, cloud audit, reputation — is later.

## Stack decision

* **Language: Python** for the MVP. Iteration speed wins; the per-call gate is a
  bounded walk over the argument object plus a few fnmatch ops, so the hot path
  is not the bottleneck. Keep the policy format and audit schema stable so a
  **Rust** reimpl of the proxy later is a drop-in (do it only when you want one
  static binary to ship or high-QPS HTTP-MCP).
* **Interception stack (agent-agnostic first):**
  1. **MCP stdio proxy** (`airlock-mcp`) — works for *every* MCP server, any agent.
  2. **Claude Code PreToolUse hook** — gates the agent's *native* tools.
  3. *(later)* HTTP/SSE MCP proxy; OS-level egress shim (eBPF / LD_PRELOAD) for plane ③.

## Week 1 — the enforcement spine ✅

| day | deliverable | status |
|-----|-------------|--------|
| 1–2 | MCP stdio MITM: JSON-RPC framing, forward both ways, block→synthesized error | ✅ `mcp_proxy.py` |
| 2–3 | Policy engine: allow/ask/block, first-match rules, modes | ✅ `policy.py` |
| 3   | Skill admission: TOFU toolset pinning + change (rug-pull) detection | ✅ `pins.py` |
| 4   | Static scan of tool descriptions (injection / poisoning flags) | ✅ `scan.py` |
| 5   | Claude Code PreToolUse hook + append-only audit JSONL + live tail | ✅ `cc_hook.py`, `audit.py` |

## Week 2 — make it real & demo-able ✅

| day | deliverable | status |
|-----|-------------|--------|
| 6–7 | Real `ask` channel: zenity approval daemon over a unix socket so `ask` ≠ `block` | ✅ `ask.py` + `askd.py` |
| 8   | Per-skill capability contract: scope fs/net/shell/tools per pinned skill | ✅ `contracts.py` |
| 9   | Batch scan mode: folder of `SKILL.md` / MCP configs → findings report | ✅ `batch.py`, `airlock scan` |
| 10  | The demo: poisoned skill → blocked credential read → red BLOCK | ✅ `demo.sh` |

## Hardening pass (post-prototype) ✅

The first prototype passed its own tests and still had five working bypasses.
Finding them was the real week-2 work; see the second table in `THREATMODEL.md`.

| fix | why it mattered |
|-----|-----------------|
| Two-pass evaluation over every argument | the policy inspected one field; the target could sit in a second one |
| Batch-aware, fail-closed pumps | a JSON-RPC array crashed the gate thread and hung the proxy |
| Hold-until-approved on toolset drift | rug pull was detected once, then silently trusted forever |
| Paginated `tools/list` pinned in full | a tool on page 2 was never pinned or scanned |
| Ordering barrier on in-flight listings | a call could be decided before admission state existed |
| Fail-closed hook | a broken policy file meant no gate at all |
| Hash-chained audit + persisted resource/detail | the log was the moat and was dropping its payload |
| `guard` mode as the default posture | default-deny on day 1 is how a firewall gets uninstalled |

## Product pass — from prototype to installable ✅

The hardening pass made it correct. It was still not a product: it could not be
installed, the default policy contained one developer's home directory, and the
only way to permit something was to hand-edit YAML.

| blocker | fix |
|---|---|
| could not be installed | `pip/pipx/uv` package; profiles and feed ship inside the wheel; no clone, no `PYTHONPATH` |
| policy hardcoded `/home/boba/Projects/*` | `${workspace}` / `${home}` / `${user}` / `${tmp}`, resolved per machine |
| `ask` was Linux + zenity only | native macOS dialog; auto-selected channel; `tty` no longer auto (it garbled the agent's TUI) |
| no install or uninstall | `airlock init` / `airlock uninstall`, idempotent, backed up, byte-exact restore |
| no way to permit what was blocked | `airlock allow last / recent / list / revoke`, folding repeated prompts into one narrow grant |
| a block was silent to the human | desktop notification with the one command that fixes it |
| one policy per machine | per-project `.airlock/policy.yaml`; three profiles: yolo / default / paranoid |
| nothing to show for a quiet week | `airlock report` — text, JSON, markdown; over-privilege section |
| overhead unknown | `airlock bench`; found and cut 0.36ms/call (fsync + contract re-parse) |
| coverage overstated | explicit table: what is gated, what is not, per agent |
| fail-closed was a code comment | documented guarantee with an enumerated degradation table |
| indicators shipped once | `airlock update` — additive feed, cannot blind the scanner |
| audit was not evidence | signing (HMAC / Ed25519), rotation with chain continuity, CEF + syslog export |
| MCP server launched via Bash bypassed everything | default-policy rules + a stated limit |

## Audit pass ✅

Six defects found by an independent reviewer, all in code paths that fire rarely
enough to have escaped a hand-driven test suite. See the table in
`THREATMODEL.md`; regressions in `tests/test_regressions.py` (40 checks).

The lesson recorded for next time: a passing suite measures the paths you
thought to exercise. Rotation, a hostile feed and a non-tty uninstall were all
things the code claimed in a docstring and nothing ever ran.

## Deep-test pass ✅

Seven rounds against the areas a feature-driven suite does not reach:
concurrency and crash integrity, fuzzing and invariants, a third adversarial
wave, failure injection, real MCP servers, soak, and the install matrix.

Four more defects found and fixed (table in `THREATMODEL.md`), the most serious
being an argument-budget evasion that let ~600 filler arguments carry a secret
path past every rule on a default install.

Standing regressions now include the concurrency and budget cases:
`tests/test_deep.py`.

## Now — what to build next

| priority | item | why |
|---|---|---|
| 1 | **Plane ① taint** — mark tool output / fetched content as untrusted, gate privileged actions whose context is tainted | the row-1/7/12 defense and the only real answer to injection |
| 2 | **Native-tool gates beyond Claude Code** — Cursor, Windsurf, Cline | the coverage table's honest gap; a mixed fleet is the normal case |
| 3 | **HTTP/SSE MCP proxy** | stdio is not where hosted MCP is going |
| 4 | **Run the feed** — publish indicators on a real endpoint with a signing key | the subscription only exists if the feed does |
| 5 | **Semantic review (stage 2)** | declared-vs-actual, the first paid-tier feature |

## Explicit cut-line (NOT in the MVP)

Semantic LLM reviewer · sandbox detonation · fleet policy / SSO / cloud audit ·
reputation graph · planes ①③ beyond argument-level checks. These are the
paid/enterprise roadmap, deliberately out of scope for the OSS wedge.

## Success = one screenshot

The launch does not need feature breadth. It needs one honest frame where
Airlock catches a real credential-exfil attempt from a popular-looking skill.
`./demo.sh` is that frame; record it.
