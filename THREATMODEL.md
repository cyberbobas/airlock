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
| `allow last` wrote grants that did nothing | the useless-grant check probed the folded glob, not the resource that was refused, so a blocked write to `~/.claude/settings.json` produced a `~/.claude/*` grant and a success message | the concrete resources are probed too; the grant is refused with the rule that blocks it |
| CEF export named a hardcoded version | a SIEM record that misstates which build made the decision is evidence about nothing in particular | it reads the package version |
| `init` replaced a symlinked config with a regular file | dotfiles-managed `~/.claude/settings.json` got the hook written to a file the real config never saw, while `doctor` reported it wired | writes resolve the link and replace its target |
| The report counted allowed asks as "escalated to a block" | it over-claimed protection, in the direction that flatters the product | escalation and unattended-allow are counted and printed separately |
| Backups collided within one second | the copy that lost was the original — the only one `uninstall` needs | backup names are made unique before writing |

## Defects found by deep testing

A third pass exercised what hand-driven tests never reach: two processes at the
same state, arguments larger than the gate reads, a broken environment, and the
install matrix. Four more defects, all in the same shape as the audit's — code
that fires rarely, so nothing ever ran it.

| defect | why it mattered | fix |
|---|---|---|
| Rotation ran outside the append lock | a second writer kept appending into the segment that had just been renamed and ledgered, so `verify` reported a truncated log with no attacker involved. Two busy agents were enough | rotation and appending serialise on a lock file that is never renamed; the lock is reentrant so the rotation anchor record can be written from inside it |
| Arguments past the inspection budget were invisible | ~600 filler arguments pushed a secret path out of the deny sweep; the call came back `ask`, which `guard` allows with no daemon. A working bypass of every secret-path rule on a default install | the budget is far larger, and exhausting it is now a refusal — "we did not read all of it" cannot report as "clean" |
| An uncapped argument blob | a 20 000-key payload built a 4 MB string and matched every glob against all of it: 2.8 s inside the gate from one call | the rendered blob is capped; every individual string is swept separately anyway |
| An empty policy enforced nothing, silently | `{}` — or a file truncated by a failed write — parses, has no rules, and under `guard` allows everything while `doctor` still looks healthy | a policy with no `rules:` key is a load error (fail closed); an explicit `rules: []` loads but `doctor` reports it as enforcing nothing |
| Secret directories were only `ask` | `*/.ssh/*` needs something after the slash, so `~/.ssh` itself fell through — `git_status ~/.ssh`, or any tool that lists a directory, walked in | directory forms added for `.ssh`, `.gnupg`, `.aws`, `.kube` |
| A repository's policy won outright | `.airlock/policy.yaml` in a cloned repo — `default: allow`, `rules: []` — turned the firewall off on a machine running the paranoid profile: `rm -rf /` allowed, `~/.ssh/id_rsa` readable, no warning. Cloning a repository is the most ordinary thing an agent does and the file is a dotfile nobody reads | a project policy is a tighten-only overlay: both are consulted, the stricter wins, its `grants:` are ignored |
| Syslog reused the CEF escaper | RFC5424 requires `"`, `\` and `]` escaped and defines no `\=`; a path containing `"] [airlock@0 effective="allow"` closed the structured-data element and opened a second one the payload controlled | separate escapers, one per format, each matching its own spec |
| One spelling of a secret path was matched, not the others | `~/%2essh/config` and a fullwidth `~/．ssh/config` walked past `*/.ssh/*` while naming that directory to anything that decodes a URI | the rendered string is NFKC-folded and percent-decoded twice before matching |
| Credential coverage stopped at ssh and aws | gcloud ADC, the GitHub CLI token, in-cluster service-account tokens, PyPI/crates.io/RubyGems/Terraform credentials, keyrings, browser cookie and password stores and shell history were all readable | all added, with a corpus asserting ordinary files with similar names still pass |
| A contract's fs scope was checked on the raw path | `normpath` does nothing for `%2e%2e`, so a percent-encoded traversal stayed "inside" a scope the plain `../` form escaped | the path is folded before `..` is collapsed |
| An unreadable grant expiry meant "never expires" | `expires: not-a-date` and `9999-99-99` both sorted later than today's string, so a malformed date granted forever — the inversion of what it means | expiries must be YYYY-MM-DD and are rejected at load; an unreadable one does not grant |
| A hold depended on being able to write it down | `check_toolset` set `held=True` in memory and saved; `is_held` re-read the file. With an unwritable `$AIRLOCK_HOME` the save failed and a rug pull went straight through — the drift was noticed and then evaporated | the hold is kept in the process too; the disk copy still wins when it is fresher |
| Deleting `audit.head` downgraded a truncation to a gap | truncating the tail and removing the checkpoint read the same as an install that predates checkpointing, so one extra `rm` chose which story the auditor saw | every live file records inside its own chain that it is checkpointed; a missing checkpoint on such a log is a deletion |
| The proxy crashed when its home was unusable | the right verdict — no server, no calls — delivered as a stack trace, with nothing naming the directory at fault | a clean refusal, exit 78 |
| Percent-decoding stopped after two rounds | `%252e` was folded and `%25252e` was not, so a triple-encoded secret path read as ordinary. The bound was a number, not a fixpoint | decoding runs to a fixpoint; the remaining cap is a runaway guard |
| A resource-scoped `allow` could fire on a call whose resource was never identified | with no known field holding it, the "primary" is the whole argument blob, so any unrelated argument could satisfy an allow glob — found by a property test, not a case | such a rule can only produce a block when the resource is unidentified; tool-scoped rules are unaffected |
| The matcher depended on a private stdlib API | `fnmatch._compile_pattern` is not promised to exist; losing it would have stopped policies loading rather than slowed them | a fallback through `fnmatch.translate`, differential-tested against the primary over 229 000 comparisons |
| A scan presented a partial read as a complete one | an unreadable directory, a file over the size cap and a clean file all produced the same silence, and the risk score was computed over whatever happened to be readable | every path not read is named, and the score says it covers the rest |
| A server could answer an id the client never sent | it could answer a call Airlock had just refused — the client saw both the refusal and a fabricated success — and could deliver "tool output" for a call that never happened: attacker-chosen content attributed to a tool, with no decision and no audit line behind it | a response whose id was never forwarded is dropped and recorded; server-initiated *requests*, which carry a `method`, still pass |
| `pins forget` reset only half of a server's admission | the pin went and the contract stayed enforced, so the next — different — toolset was refused tool by tool with "not in pinned contract" while `pins list` showed a healthy new pin: two subsystems telling the operator contradictory stories | forget stops enforcing the contract too and says so; the contract stays on disk for review |
| A failed `allow revoke` reported success | `airlock allow revoke 5 && echo gone` printed "gone" for a grant that was never there | exit 1 for a grant that is not there, 2 for an index that is not a number |
| A human answering after the timeout was recorded as an approval | the daemon wrote the record before sending the reply, so an answer that reached nobody still left `ask_prompt effective=allow` in the log — next to, and after, the `decision effective=block` for the same call. A log that records an approval for a call that did not run is worse than no record | the reply goes first; an answer the caller never received is recorded as an answer that decided nothing, and `airlock report` says how many arrived too late |
| The policy was observable half-written | `allow revoke` and the profile writer truncated in place. A prefix of a YAML rule list is still valid YAML — 104 of the 118 line-boundary truncations of the shipped paranoid profile parse as a policy, the worst with one block rule left of seventy-two — so a gate reading at that instant would enforce almost nothing and log it as an ordinary decision | every write of security state goes through `config.write_atomic`: tmp file, then `os.replace` |
| An `ask` handed to the agent's own prompt had no recorded answer | Airlock logged the question and stopped. Claude Code asked the human, and whatever they said never came back, so an approved call and a refused one left an identical log — for exactly the calls worth interrupting somebody over | `init` wires PostToolUse as well; a call that ran says so, and `airlock report` pairs each handed-over ask with whether it ran |
| `airlock hook --post` exited 2 instead of recording | argparse rejected the option before REMAINDER saw it, and `init` writes that form whenever the console script is not on PATH — an error on every single tool call | passthrough commands are split off before parsing |
| The gate ran `git` from the caller's PATH on every decision | `${workspace}` was resolved with `git rev-parse`, twice per gated call. A `git` earlier on PATH both executes inside the gate and decides what `${workspace}` means — with one that answered `rev-parse` with a directory of its choosing, a read that was `ask` under paranoid became `allow` | the enclosing repo is found by walking up for a `.git`; no subprocess, no PATH |
| `git init ~` widened every `${workspace}` rule | a repository whose root is the home directory is not a project, and treating it as one scoped every allow rule to the whole of $HOME — and creating it is a command an agent can run | $HOME and / are not accepted as repo roots, and `doctor` warns when the workspace is the home directory anyway |
| A swapped policy left no trace | `AIRLOCK_POLICY=/tmp/anything` and `AIRLOCK_MODE=observe` each switch enforcement off, and the records they produce read like ordinary ones — `rm -rf /` allowed, reason "default policy". Nothing in the log said which policy had decided | every enforcement point fingerprints its own configuration and records one line whenever it changes; `airlock report` leads with the count |
| Shell environment files were only `ask` | `~/.zshenv` is read before every non-interactive zsh, so writing one line there set `AIRLOCK_MODE=observe` for every later gate process — and under `guard` an unattended ask is an allow, so nobody was asked | those files and the weakening variables are blocked outright, with a corpus checking that `profile.csv` and `env.ts` still pass |
| Tool poisoning was detected and then ignored | the scanner found three high-severity indicators in a tool description at admission, recorded all three, admitted the server and gated its calls exactly as for a clean one. Detection that changes no decision narrows nothing, which is what the static stage exists to do | a high-severity finding in a description holds the whole toolset on the same mechanism as a rug pull, until `airlock pins approve`; `yolo`, which escalates nothing, is unaffected |
| The risk score could not tell a security codebase from an attack | every file was weighted alike and every `.md` counted as an instruction, so Airlock's own repository scored 100/100 on 241 high findings — the same as a skill that steals keys. "We scanned N public skills and here is what we found" cannot rest on a number like that | findings are weighted by the kind of file they sit in, scored from the strongest evidence rather than the volume, and the top of the scale needs intent (`injection`/`stealth`) or a credential flow (`secrets` with `exfil`) in something an agent reads as instructions |
| The static report and the running gate never looked at each other | `airlock scan` could name a server the gate was holding, or one it had never admitted, and say nothing about either | the report carries each server's admission state |

What deep testing confirmed rather than broke: 480 concurrent audit records with
no loss or tearing, 20 concurrent pins with exactly one `new`, an audit chain
that survives repeated `SIGKILL` mid-write, 4 000 calls at ~900/s with flat
memory and no descriptor leak, and identical behaviour installed as a wheel,
an sdist, editable, via `uv tool` and via `pipx`, on Python 3.13 and 3.14.

## Defects found by the fifth deep round

Rounds aimed at what a feature suite structurally cannot reach: the newest code
under adversarial load, the MCP stream at byte level, forging the audit rather
than corrupting it, syscalls failing mid-write, and random command sequences
against a reference state machine.

| defect | why it mattered | fix |
|---|---|---|
| The project overlay's *default* tightened every decision | the natural way to write an overlay is a couple of extra rules and nothing else — and that reclassified every ordinary call as `ask`, which under `paranoid` is a refusal. Adding one rule to a repo stopped the agent reading its own source | only what the overlay says on purpose tightens: a rule it wrote, or its refusal of an oversized payload. A repo wanting default-deny still sets `default:`, which is merged at load |
| Tail truncation was invisible | the ledger only covered rotated segments, so deleting the last lines of the live file — exactly where someone covering their tracks cuts — verified as an intact chain | every record updates a signed tail checkpoint; removing even one record is now a mismatch, and `airlock verify` has a third exit code for "verified but the checkpoint is missing" |
| Unsigned records were tolerated while signing was on | the downgrade was free: delete the checkpoint, strip every signature, rewrite history, recompute the chain — and the log called itself intact | unsigned records fail verification when signing is configured |
| A failing disk killed the proxy's pump thread | `pins.save` and `contracts._save` let `OSError` escape into the server-to-client pump, so a full disk stopped the agent receiving responses at all. An outage caused by bookkeeping | persistence failures are returned, not raised; the pump cannot be killed by admission bookkeeping; a pin that could not be written is logged as degraded rug-pull detection |
| `pins reject` invented a hold | rejecting a server with nothing pending set `held=True`, so a mistyped server id blocked every call to a healthy server. It also discarded the pending entry, so the rejected toolset read as a fresh drift and a later `approve` found nothing to adopt | rejecting nothing is a no-op; a rejection is remembered, keeps the hold, reports itself as rejected, and `approve` can still override it |

Also from this round, not a defect but worth recording: the rule matcher was
re-globbing the tool name once per rule per string. Hoisting that and compiling
each `match` once took a decision from 250 µs to 22 µs and the per-call proxy
overhead from 0.66 ms to 0.47 ms. The change was proven behaviour-preserving
against the old matcher over 317 patterns × 48 texts and 4 000 random decisions
before it was kept.

## Defects found by the sixth deep round

Aimed at the newest code and at three things a feature suite never looks at:
whether the two enforcement points answer the same question the same way, what
is left running after a signal, and whether the report's arithmetic closes.

| defect | why it mattered | fix |
|---|---|---|
| The hook enforced neither holds nor contracts | Claude Code routes MCP calls through PreToolUse as `mcp__server__tool`, so both gates see the same call. A server the proxy was HOLDING for a rug pull or tool poisoning had its calls allowed by the hook, and a per-skill contract did nothing there at all. The "calls held" guarantee had a second door | the hook resolves the server id from the tool name and applies the hold and the contract, so the two gates agree |
| An agent reads instructions from more than `SKILL.md` | the same key-stealing payload scored 90 in `skills/SKILL.md` and 10 in `.claude/commands/deploy.md` — a slash command injected into the prompt verbatim. Subagent definitions, Cursor rules and `copilot-instructions.md` had the same discount; YAML and TOML prompts were not read at all; and `.github` was skipped entirely by a `startswith(".git")` filter. The false-positive fix had produced a false negative | instruction *locations* are recognised, skill frontmatter promotes a file wherever it sits, data files are scanned, and `.git` is skipped without swallowing `.github` |
| A signal orphaned the MCP server | SIGTERM/SIGINT/SIGHUP stopped the proxy and left its child running: a process holding the credentials and sockets it was given, with no gate in front of it and no parent. Restarting an agent a few times accumulated them | the proxy terminates its child on a signal and on every exit path, insisting with SIGKILL after a grace period |
| The approval daemon left its socket behind | a supervisor sends SIGTERM, not `^C`. The default action killed the daemon and the socket stayed on disk, after which every `ask` connected to nothing, waited out the timeout and refused — while `doctor` reported that asks would reach a human | the daemon cleans up on SIGTERM/SIGHUP, and the ask channel probes the socket rather than trusting that the file exists |
| Syslog MSG could forge a second SD element | the structured-data half was escaped correctly, but the free-text half carried the reason raw. RFC5424 says MSG is not parsed as SD and a compliant parser agrees; the regex-based SIEM pipelines that are just as common do not. The same forgery that was fixed one field over, moved into MSG | the SD-ID marker is neutralised wherever it appears, and the reason is carried properly escaped inside the real SD element |

What this round confirmed rather than broke: the poisoned-toolset hold holds
across restarts, catches poison in a parameter description, refuses to be
laundered by a server that later serves a clean toolset, releases on
`airlock pins approve`, does not fire on a medium-severity phrase, and does not
hold `mcp-server-time`, `mcp-server-git` or `mcp-server-fetch`. The report's
totals, per-effect counts, reason sums, ask breakdown, per-server sums and
rendered percentages all reconcile against `audit.jsonl`.

## Matching is by string, not by resolved identity

Two limits worth stating plainly, because both are reachable:

* **Symlinks are not resolved.** Airlock matches the path the agent asked for.
  A link named innocently that points at `~/.ssh` is followed by the OS, not by
  the gate. Containment against that needs a sandbox or an LSM, not a policy.
* **A secret split across separate arguments is not reassembled.** Each string
  is inspected on its own, so `["~", ".ssh", "id_rsa"]` passed to a tool that
  joins its own arguments is three innocent strings to the gate.

Both are consequences of gating at the call boundary rather than at the syscall.
They are the honest edge of what this layer can claim.

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
