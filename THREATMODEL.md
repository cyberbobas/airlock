# Airlock threat model (STRIDE)

STRIDE letters: **S**poofing · **T**ampering · **R**epudiation ·
**I**nformation disclosure · **D**enial of service · **E**levation of privilege.

Column *status*: ✅ enforced by the runtime gate · ◐ partial (stated limit) ·
○ mapped, not built.

| # | Attack | STRIDE | Plane | Mechanism (the gate) | Status |
|---|--------|--------|-------|----------------------|--------|
| 1 | Indirect prompt injection via tool output / fetched web page | T,E | ① Ingress | taint untrusted input; gate privileged action on the trust-level of the context that motivated it | ○ |
| 2 | Tool poisoning — hidden instructions in an MCP tool *description* | T,S | ④ Supply | static scan of descriptions at admission + semantic review | ◐ scan only |
| 3 | Rug pull — a trusted skill silently ships a new, malicious version | T | ④ Supply | TOFU hash-pin; on change **all calls held** until `airlock pins approve` | ✅ |
| 4 | Credential exfiltration — read `~/.ssh`/`.env`, then POST it out | I | ③ Exfil + ② Action | secret-path block over **every** argument + egress allow-list + contract | ✅ |
| 5 | Destructive action — `rm -rf /`, `DROP TABLE`, force-push | D,T | ② Action | policy block / human-ask on destructive patterns | ✅ |
| 6 | SSRF to cloud metadata (`169.254.169.254`) | I,E | ③ Exfil | deny-list for link-local/metadata + host allow-list | ◐ argument-level |
| 7 | Confused deputy — agent's legit creds used for the attacker's goal | E | ①+② | taint + human-in-the-loop when action is privileged *and* context is tainted | ○ |
| 8 | Unattributed action — no record of who/what did it | R | ⑤ Identity | hash-chained append-only log; `airlock verify` finds any edit | ◐ evidence, unsigned |
| 9 | Capability creep — skill uses more than it declared | E | ④ Supply | observe mode records the real footprint; contract enforces the grant | ✅ |
| 10 | Supply-chain pull — skill fetches a malicious npm/pip package | T,E | ④ Supply | static scan + `airlock scan` flags unpinned `npx -y` + sandbox detonation | ◐ scan only |
| 11 | Context flooding / cost DoS to bury a payload or exhaust budget | D | ① Ingress | ingest size caps + anomaly flag | ○ |
| 12 | Memory / RAG poisoning — planting instructions in the agent's store | T | ① Ingress | provenance tag on stored context; tainted memory can't authorize actions | ○ |

## Attacks on Airlock itself

A gate is only worth what it survives. These were live bypasses of the first
prototype; each is now a case in `tests/test_redteam.py`.

| Bypass | Why it worked | Fix |
|---|---|---|
| Decoy argument — `read_note{name:"todo", path:"~/.ssh/id_rsa"}` | the engine rendered one "primary" field and matched rules against that alone | two-pass evaluation: every string in the payload, nested ones included, is checked against the block rules |
| JSON-RPC batch array | `msg.get()` on a list raised, killed the pump thread, and the proxy hung with the gate off | batches are gated element by element; any gate exception fails closed |
| Rug pull once, then trusted | the pin file was overwritten with the new hash at detection time | the old pin stays authoritative; the new hash is parked as `pending` and calls are held |
| Tool hidden behind `nextCursor` | only the first page of `tools/list` was pinned and scanned | pages are accumulated; pinning happens on the complete list |
| Call overtaking its own `tools/list` | admission state was read before the listing came back | a `tools/call` waits for an in-flight listing to settle |
| Broken policy file | the hook raised, exited 1, and Claude Code treated that as non-blocking | the hook exits 2 (block) unless `AIRLOCK_FAIL_OPEN=1` |
| Spelling around a rule — `rm  -rf /`, `rm -fr /` | one narrow glob per pattern | wider globs plus scan-flag escalation as a second net |

## Defects found by independent audit

A second pass by someone who had not written the code found six defects that the
suite did not. The pattern is worth recording: everything exercised by hand
worked; what failed was what fires rarely — rotation at 64 MB, a hostile feed, a
non-interactive uninstall. Each now has a regression in `tests/test_regressions.py`.

| defect | why it mattered | fix |
|---|---|---|
| Rotation started each segment at genesis | `verify` reported tampering on an untouched log the moment it passed the size cap — an integrity alarm that fires on its own teaches people to ignore it | the new segment chains onto the previous one's last digest; rotations are recorded in a ledger so a dropped segment is also detected |
| A hostile feed could blind 4 of 5 shipped indicators | the "cannot blind" guarantee only covered `scan.py`; half the indicators ship in `data/feed.json` | the bundled feed is a floor — an update merges on top and may raise a severity, never lower or remove one |
| Feeds installed unsigned by default | the detection rules of a supply-chain tool are themselves a supply chain | signature required; `--allow-unsigned` is explicit |
| `uninstall` raised `EOFError` without a tty | a traceback handed to someone removing the product, and unusable from CI | non-interactive callers are told to pass `-y` |
| `@modelcontextprotocol/server-*` bypassed the out-of-gate rule | the commonest spelling of an MCP server fell through to a generic ask, which `guard` allows | namespace patterns added and tested for every launch form |
| The rotation ledger protected the log but nothing protected the ledger | it was plain unsigned JSONL that nothing referenced: deleting a segment *and* its one ledger line reported `CHAIN INTACT across 46 records` while 14 had vanished | the ledger is chained and signed, and every handover is anchored by a record inside the log — the two now have to agree |
| Rotation stopped rotating inside a busy second | second-resolution segment names collided, `dest.exists()` returned, and the log grew past its cap until the clock ticked | microsecond stamps that bump on collision and still sort chronologically |
| A hostile feed could hang the gate outright | feed patterns run in-process on every call and `re` cannot be interrupted: `(a+)+$` against forty characters never returned, so the proxy never answered and the agent hung. "Noisy, never blind" was true; "never wedged" was not | patterns are refused at install time if they nest an unbounded quantifier or fail timed probes in a killable child; scanned text is capped |
| The hook exited 1 when `$AIRLOCK_HOME` was unusable | Claude Code blocks on exit 2 and *carries on* for every other code — the traceback was an allow | any escape from `main()` lands on 2 unless `AIRLOCK_FAIL_OPEN=1` |
| Self-protection was scoped to `Bash` | an agent with a Write tool never needed a shell to add an ungated MCP server or delete the hook, and an unattended `ask` is an allow under `guard` | `.mcp.json` and `.claude/settings*.json` are blocked for every tool |
| `airlock log` could be made to print a line that never happened | a file path containing a newline printed a second, fabricated decision; an ANSI escape could erase the real ones | control characters are escaped wherever a record is rendered |
| `audit.jsonl` was 0644 while rotated segments were 0600 | the file holding the freshest paths, hosts and commands was the least protected one | the live file is chmod 0600 on creation |
| Metadata SSRF only matched the dotted form | `http://2852039166/` is the same address; so are the hex, octal, v6-mapped and `nip.io` spellings | all six forms blocked, with a test that ordinary paths still are not |
| `*fetch*` never matched `WebFetch` | fnmatch is case-sensitive on POSIX, so the shipped allow-list example silently never fired | tool patterns match case-insensitively, as the profiles always said |
| The report counted allowed asks as "escalated to a block" | it over-claimed protection, in the direction that flatters the product | escalation and unattended-allow are counted and printed separately |
| Backups collided within one second | the copy that lost was the original — the only one `uninstall` needs | backup names are made unique before writing |

## The load-bearing assumption

Rows 1, 7, 12 (injection-class) **cannot be scanned out** — natural language has
no grammar for "malicious". Their real defense is architectural: taint tracking
+ a least-privilege runtime contract + human-in-the-loop on the
`privileged × tainted` intersection. Static scan (rows 2, 10) and pinning
(row 3) *narrow* the contract; runtime enforcement (rows 4, 5, 9) *holds* the
boundary. Airlock proves the holding layer first, because that is the part a
static scanner cannot reach.

## Fail-closed, enumerated

Where a security tool degrades matters as much as what it blocks.

| failure | what happens | override |
|---|---|---|
| policy file missing or malformed | hook exits 2 (block); proxy refuses to start (exit 78) | `AIRLOCK_FAIL_OPEN=1` |
| the gate raises an exception | the call is refused with the error, not forwarded | none |
| a pump thread dies | the proxy answers refusals rather than passing traffic | none |
| toolset changed since pinning | every call to that server is held | `airlock pins approve` |
| `ask` reaches nobody | `paranoid` refuses; `default` allows and reports it | profile choice |
| hook payload unparseable | logged and allowed (a harness change, not an attacker) | `AIRLOCK_STRICT=1` blocks |
| indicator feed unreachable or corrupt | built-in indicators keep working | none needed |
| indicator feed unsigned or tampered | refused; the previous feed stays installed | `--allow-unsigned` |
| indicator feed hostile but installed | the bundled floor still fires; it can add, never remove | none |
| audit log rotates | the chain continues into the new segment; the rotation is recorded in a ledger | none |
| a whole audit segment is deleted or truncated | `verify` names the missing segment | none |
| a feed pattern backtracks catastrophically | it never installs: refused at update time, before it can run on a call | none |
| Airlock's own setup is broken (unusable `$AIRLOCK_HOME`) | the hook exits 2 — a gate that cannot start does not wave calls through | `AIRLOCK_FAIL_OPEN=1` |
| a ledger line is edited, removed or the ledger deleted | the ledger's own chain breaks, or the anchor record in the log names an entry the ledger no longer has | none |
| two rotations land in the same second | segment names carry microseconds and bump on collision, so rotation keeps rotating | none |
| audit log unwritable | the decision is still enforced | none |

## Known limits

* **Same-privilege attacker.** An agent that can write `policy.yaml`,
  `pins.json` or `$AIRLOCK_HOME` can disable its own gate. Keep them outside
  the workspace the agent writes to. Enforcing that needs OS-level separation.
* **The audit log is tamper-*evident*, not tamper-proof.** Append is always
  possible; only rewriting is detectable. Signing needs a key the agent cannot
  read — a fleet-service concern.
* **Egress is argument-level.** Airlock sees URLs passed to gated tools. A
  process that opens its own socket is invisible until plane ③ has an
  OS-level shim (eBPF / LD_PRELOAD).
* **stdio transport only.** HTTP/SSE MCP servers are not proxied yet.
* **Only Claude Code's native tools have the second gate.** Cursor, Windsurf,
  Cline and Codex get MCP mediation (which is the broad surface) but their
  built-in file and shell tools run ungated. See the coverage table in README.
* **A shell can start an MCP server outside the proxy.** The default policy
  blocks `npx …mcp-server…`, `claude mcp add` and edits to `.mcp.json`, but a
  determined agent with shell access and a novel spelling gets around a string
  match. Containment at this level needs a sandbox, not a policy rule.
* **Signing is only as good as key separation.** HMAC with a key in
  `$AIRLOCK_HOME` protects a shipped-off log, not against a process running as
  you. Use `AIRLOCK_SIGN=ed25519` with the private key held elsewhere when the
  log has to be evidence.
