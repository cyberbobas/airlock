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

## Fifth deep round ✅

Six more rounds: the newest code under adversarial load, byte-level protocol
fuzzing, audit forgery, syscall fault injection, model-based state testing, and
a 50 000-call soak. Five defects (table in `THREATMODEL.md`) plus a 10x on the
hot path, proven behaviour-preserving before it was kept.

Standing suites: `tests/test_audit.py` for the integrity story on its own,
`tests/test_deep.py` for robustness, overlay and matcher checks in
`tests/test_policy.py`.

## Sixth deep round ✅

Five defects (table in `THREATMODEL.md`), the two most consequential being the
hook ignoring holds and contracts — which gave the plane-4 guarantee a second
door — and the scanner discounting every agent-instruction file that is not
named `SKILL.md`.

Standing suite: `tests/test_lifecycle.py` for signals, orphans and whether the
two gates agree; scanner-classification regressions in `tests/test_boundary.py`.

## Now — what to build next

The next work is **not** full plane-① taint and **not** a second scanner.
Those are either a research program or an occupied category. The holes we
can fail-close, that nobody else fail-closes on a developer laptop, are
documented with demos, limits and phasing in [`docs/ROADMAP.md`](docs/ROADMAP.md).

Short version (unique first, coverage as a dependency):

| tag | unique work | why it is empty |
|---|---|---|
| 0.5 | **U1 sampling/elicitation/roots deny** + **U6 prompts/notifications gated** | server-initiated MCP requests currently *pass*; Unit 42 sampling attacks have no local deny |
| 0.6 | **U2 consent integrity (LITL)** + **U3 census** + **U4 subagent principal** | humans approve the agent's story; hidden instruction files have no inventory+hold |
| 0.7 | **U5 egress-publish** + **U9 taint-lite** + **U8 `airlock breach`** | git/gist/issue are not "URLs"; IR from a hash-chain does not exist as a CLI |
| 0.8 | **U7 inbound fence** + **U10 shadow-MCP + Landlock child** | always-on agents die on ingress; the documented bypass is "start MCP outside the proxy" |

Coverage of real MCP stores, `doctor --fix`, and an honest indicator feed
are required so the unique commands are not lying. HTTP/SSE MCP is 0.8,
after sampling is denied on stdio. Semantic review, fleet/SSO, full taint,
canaries, drift and a general sandbox product stay on the cut-line.

## Explicit cut-line (NOT the OSS wedge)

Semantic LLM reviewer · sandbox-as-product (Claude/Codex/nono already ship)
· fleet policy / SSO / cloud audit · reputation graph · token-level taint ·
canary tokens · behavioral drift · session cost dashboards. Occupied or
enterprise. Named in `docs/ROADMAP.md`.

## Success = one screenshot, then three more

The launch of 0.4.x still needs one honest frame where Airlock catches a
real credential-exfil attempt from a popular-looking skill. `./demo.sh` is
that frame; record it.

0.5–0.7 succeed only if they add frames the spine cannot produce:

1. Server never called a tool — sampling died at the proxy.
2. Claude said "security review" — Airlock showed `curl | bash`, digest-bound.
3. `airlock census` on a default machine: ungated instruction files, one held.
