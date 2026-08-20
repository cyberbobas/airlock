# Airlock — runtime firewall for AI coding agents

Gate every tool call, MCP call and skill your agent runs against a
least-privilege policy. Static scanners check a skill once, before install.
Airlock sits in the call path and decides **this call, right now** — which is
where a skill that reads clean and behaves badly actually gets stopped.

```
 agent ──native tools──▶ [PreToolUse hook] ─┐
                                            ├─▶ policy ─▶ allow / ask / block
 agent ──MCP stdio──▶ [airlock-mcp] ──▶ server ─┘         │
                                                          ▼
                                          audit.jsonl (hash-chained, signable)
```

## Install

```bash
pipx install airlock-agent      # or: uv tool install airlock-agent
airlock init                    # wires the hook, wraps your MCP servers
airlock doctor                  # confirms what is actually enforcing
```

`airlock init` backs up every file it edits and marks every line it adds.
`airlock uninstall` removes exactly those lines and restores the original file
**byte-for-byte**, formatting included — it writes back the backup rather than
re-serialising, so nothing shows up in your git diff. If you edited the file
after installing, your edits win and it falls back to a semantic unwrap.
`--purge` also deletes Airlock's own data.

Both are safe to run non-interactively: without a tty they ask you to pass `-y`
rather than prompting.

Requires Python 3.11+. macOS and Linux. One dependency (PyYAML).

## The first five minutes

```bash
airlock init --profile default   # block the dangerous, stay out of the way
# ... work normally for a while ...
airlock allow recent             # what got in your way, most frequent first
airlock allow last               # permit it, narrowly, in one command
airlock report                   # what the week looked like
```

## Profiles — pick a posture, don't read YAML

| profile | explicit `block` rules | call no rule matched | `ask` with no human | for |
|---|---|---|---|---|
| `yolo` | logged, **not** blocked | allowed | allowed | week one: learn what your agents do |
| `default` | **blocked** | allowed + logged | allowed + logged | day-to-day |
| `paranoid` | **blocked** | asks a human | **refused** | a production repo, a regulated codebase |

```bash
airlock profile              # which one is active, and why
airlock profile paranoid     # switch
```

The intended path is `yolo` → `default` → `paranoid`: learn, then guard, then
tighten. A firewall that gets in the way on day one is the one that gets
uninstalled, so `default` blocks only what is unambiguously dangerous.

## When something is blocked

You get a desktop notification saying what and why, the agent gets a refusal it
can read, and one command fixes it:

```bash
airlock allow last                        # grant the thing you were just stopped on
airlock allow last --expires 2026-12-31   # ...until a date
airlock allow notes read_note --match '/data/*'
airlock allow list                        # what you have granted
airlock allow revoke 2
```

`allow last` folds together every time the same call was gated and proposes the
tightest grant that covers them — usually one directory instead of twelve files.

**A grant can never lift an absolute block.** Secret paths, `rm -rf /`, cloud
metadata, known exfil collectors and download-and-execute are checked *before*
grants, against every argument. `airlock allow` will tell you it refused rather
than write a grant that quietly does nothing.

## What is actually covered

Being precise about this matters more than the feature list, because a mixed
fleet is the normal case.

| surface | covered | how |
|---|---|---|
| **Any MCP server, any agent** (stdio) | ✅ | `airlock-mcp` proxy — vendor-neutral, this is the broad one |
| Claude Code native tools | ✅ | PreToolUse hook |
| Cursor / Windsurf / Cline / Codex native tools | ❌ | their MCP servers are gated; their *built-in* file and shell tools are not |
| MCP over HTTP/SSE | ❌ | stdio only today |
| A process opening its own socket | ❌ | needs an OS-level egress shim (plane ③) |
| A shell command launching an MCP server directly | ⚠️ | blocked by a policy rule, not by the OS — see Limits |

If your team is on mixed agents: every agent's **MCP** traffic is gated the same
way. Only Claude Code's own built-in tools currently get the second gate. We
would rather say that than have you find out during a rollout.

## Fail-closed, on purpose

This is a security property, not an implementation detail:

* If the **policy will not load**, the hook exits 2 (block) and the proxy
  refuses to start. No policy means no boundary, so it does not run without one.
  `AIRLOCK_FAIL_OPEN=1` inverts this, knowingly.
* If the **gate itself throws**, the proxy answers with a refusal rather than
  forwarding. An exception in the firewall is not an open door.
* If a **toolset changes** after it was pinned, every call to that server is
  held until a human approves — detection that auto-accepts is not a control.
* If an **`ask` cannot reach anyone**, `paranoid` refuses and `default` allows
  and says so in the report. Which of those you want is a profile choice, made
  explicitly, not a silent default.

## Overhead — measured, not assumed

```
policy decision      p50   115 µs    p99   685 µs
MCP call, direct     p50  0.064 ms   p99  0.079 ms
MCP call, gated      p50  0.543 ms   p99  0.749 ms
added by Airlock     p50  0.480 ms   p99  0.670 ms
peak RSS             27 MB
```

Python 3.14, Linux. Reproduce with `airlock bench`. For scale: one model turn is
hundreds of milliseconds at best. The gate is not where your agent spends time.

Audit durability is tunable: `AIRLOCK_AUDIT_FSYNC=critical` (default) fsyncs
blocks and asks but not the routine allow flood; `always` for compliance.

## Scan before you install

```bash
airlock scan ~/.claude/skills          # a folder of SKILL.md
airlock scan ~/.claude/settings.json   # MCP server defs AND hook commands
airlock scan ./skill --json            # machine-readable
airlock scan ./skill --fail-on-findings # exit 1 in CI
```

Reports injection / secret-access / exfil / stealth indicators with line
numbers, enumerates every MCP server definition, and says which are **not**
behind Airlock. Indicators are evidence for a human, never a verdict.

## Indicators that stay current

Collector hosts and injection phrasings rot like antivirus signatures.

```bash
airlock update            # refresh the indicator feed (requires a signature)
airlock update --status   # what is active, and what it sits on top of
```

**Unsigned feeds are refused.** A tool that exists because people install code
they have not read does not get to fetch its own detection rules over plain
HTTPS and trust the answer. Set `AIRLOCK_FEED_KEY` to the feed's key, or pass
`--allow-unsigned` for a feed you host yourself.

**The bundled indicators are a floor.** An update is merged *on top of* both
`scan.py`'s patterns and the `data/feed.json` that shipped in the wheel. It can
add indicators and raise a severity — it cannot delete one or lower a severity.
So a poisoned feed can make Airlock noisy; it cannot make it blind. (This was
only half true before an audit: half the indicators live in the bundled feed,
and an update that redefined them switched those detections off.)

## Rug pull: detected *and* held

```
$ airlock pins
  repo-tools  [HELD]
    hash    7bf9f6f2f032ca70…
    pending a91c4e0b22d7f118…  seen 2026-08-21T09:12:44Z
      + run_command
      airlock pins approve repo-tools
```

While a server is held **every call it receives is blocked**, including ones the
policy would allow.

## Per-skill contracts

Global policy answers "may *any* skill do X?". A contract answers "may *this*
skill do X?".

```bash
AIRLOCK_MODE=observe   # ... run for a while: records each server's real footprint
airlock contracts list
airlock contracts promote notes   # turn what was observed into an enforced grant
```

```yaml
notes:
  enforced: true
  tools: [read_note]
  fs:   ["*/notes/*"]
  net:  []
  shell: false
  default: block
```

Every string in the argument object is classified — not just the primary one —
so the target cannot be hidden in a second argument.

## Evidence

```bash
airlock log -n 40                 # recent decisions with their concrete targets
airlock verify                    # chain intact, or the exact line where it broke
airlock export --format cef       # into ArcSight / Splunk
airlock export --format syslog    # RFC5424
airlock report --markdown         # the page you send your manager
```

Every record carries `prev` + `h`. Editing or deleting any past line breaks
every digest after it. The chain **continues across rotations** — a new segment
starts from the previous one's last digest — and every rotation is written to a
ledger, so deleting or truncating a whole segment is reported too:

```
$ airlock verify
  CHAIN BROKEN  audit segment audit-20260820081301.jsonl is missing
                — 2026-08-20T08:13:01Z rotation was deleted
```

That is tamper *evidence*.

For attribution, enable signing:

```bash
AIRLOCK_SIGN=hmac       # local key at $AIRLOCK_HOME/audit.key
AIRLOCK_SIGN=ed25519    # AIRLOCK_SIGN_KEY -> a key the agent cannot read
```

HMAC with a local key protects a log once it leaves the machine, not against a
process running as you. Ed25519 with the private key held elsewhere is the real
answer; we say so rather than calling the cheap one "signed audit".

## Per-project policy

Resolution order — first hit wins:

1. `AIRLOCK_POLICY`
2. `.airlock/policy.yaml` or `.airlock.yaml` in the repo (walking up to its root)
3. `$AIRLOCK_HOME/policy.yaml` (yours, written by `airlock init`)
4. the bundled profile

So a team can commit a strict policy to the repo it applies to while a personal
machine-wide one covers everything else. Paths use `${workspace}`, `${home}`,
`${user}`, `${tmp}` — no absolute paths in a shared file.

## Commands

| | |
|---|---|
| `init` · `uninstall` · `profile` · `doctor` | setup |
| `allow` · `check` · `log` · `report` | daily |
| `scan` · `pins` · `contracts` · `update` | admission |
| `verify` · `export` | evidence |
| `bench` | overhead |
| `mcp` · `hook` · `askd` | runtime |

## Config

* `AIRLOCK_MODE=observe|guard|enforce` — override the profile's posture.
* `AIRLOCK_POLICY`, `AIRLOCK_HOME`, `AIRLOCK_WORKSPACE`, `AIRLOCK_PROFILE`
* `AIRLOCK_ASK_BACKEND=socket,osascript,zenity,tty,fallback`
* `AIRLOCK_ASK_TIMEOUT=60` · `AIRLOCK_ASK_TTY=1`
* `AIRLOCK_NOTIFY=0` — no desktop notification on block.
* `AIRLOCK_FAIL_OPEN=1` · `AIRLOCK_STRICT=1`
* `AIRLOCK_SIGN=hmac|ed25519` · `AIRLOCK_SIGN_KEY` · `AIRLOCK_VERIFY_KEY`
* `AIRLOCK_AUDIT_FSYNC=critical|always|never` · `AIRLOCK_AUDIT_MAX_MB=64`
* `AIRLOCK_FEED_URL` · `AIRLOCK_FEED_KEY`
* `AIRLOCK_QUIET=1` — log only, no live stderr line.

## Limits

A security tool that oversells its boundary is worse than none:

* **It does not stop prompt injection.** Nothing does. Airlock gates the
  *action* the injection asks for.
* **Plane ① (ingress) is unbuilt.** Tool output is not taint-tracked, so
  "privileged action × tainted context" cannot yet be a rule.
* **Egress is argument-level.** URLs passed to gated tools are seen; a process
  opening its own socket is not.
* **An agent with a shell can start an MCP server outside the proxy.** The
  default policy blocks the obvious spellings, but that is a policy rule, not an
  OS boundary. Real containment needs a sandbox.
* **An agent that can write your policy can disable its own firewall.** The
  default policy blocks writes to `.airlock/` and `policy.yaml`; keep them
  outside the workspace the agent writes to anyway.
* **Non-Claude-Code native tools are ungated.** See the coverage table.

See `THREATMODEL.md` for the attack-by-attack table, including the bypasses this
project has already lost to once.
