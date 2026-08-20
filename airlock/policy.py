"""Policy engine — shared by the MCP proxy and the Claude Code hook.

A decision is one of: allow / ask / block. Rules are evaluated top to bottom,
first match wins, else the default action applies. A rule matches when the tool
name matches (fnmatch) AND, if present, its `match` glob matches a rendered
"action string" for that tool call.

EVALUATION ORDER
---------------
1. **Absolute blocks.** Every `block` rule is checked against the primary field
   AND every other string in the arguments — nested dicts and lists included.
   A block here wins outright: no grant, no allow rule, no contract can lift it.
   Without the sweep, `read_note{name:"todo", path:"~/.ssh/id_rsa"}` renders as
   "todo" and sails past every secret-path rule; that was a real bypass.
2. **Grants.** Reviewed exceptions written by `airlock allow`. A grant makes a
   call allowed without anyone hand-editing YAML — which is the difference
   between a policy people tune and a product people uninstall.
3. **Rules.** First match wins (allow / ask / block).
4. **default.**

Because step 1 runs first, a grant can never widen the blast radius past the
hard blocks. That is what makes `airlock allow last` safe to offer.

Global mode (env AIRLOCK_MODE) — the friction dial, lowest to highest:

  observe  learn only. Nothing is ever blocked, everything is logged, and each
           skill's actual fs/net/shell footprint is recorded as a contract
           proposal. Use this for the first days on a new machine.

  guard    the shipped default. Explicit `block` rules are enforced; a call no
           rule matched is ALLOWED and logged, and an `ask` with no human
           available is allowed rather than refused. Catches the dangerous
           without standing in front of the ordinary — a firewall that gets in
           the way is the one that gets uninstalled.

  enforce  default-deny. Anything not explicitly allowed asks, and an `ask`
           with no human collapses to `ask_fallback` (block). Promote to this
           once observe has produced contracts you trust.

`ask` has no interactive channel inside the stdio proxy, so it collapses to
`ask_fallback` there (default: block). The Claude Code hook maps ask -> the
agent's own approval prompt, so a human still decides.
"""
from __future__ import annotations
import fnmatch
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import config

ALLOW, ASK, BLOCK = "allow", "ask", "block"
OBSERVE, GUARD, ENFORCE = "observe", "guard", "enforce"
MODES = (OBSERVE, GUARD, ENFORCE)

# strictness ordering: block is strictest, allow is loosest
RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}

# Bounds for the deny sweep, so a pathological payload cannot burn the hot path.
#
# These are not just performance knobs: whatever they cut off is a part of the
# payload the gate did not read. A budget of 512 values meant ~600 filler
# arguments pushed a secret path out of view entirely, and the call came back
# `ask` — which `guard` with no daemon then allows. So the budget is generous
# enough that real calls never reach it, and reaching it is itself a refusal
# rather than a silent gap. Raise them deliberately if a real workload needs it.
_MAX_DEPTH = int(os.environ.get("AIRLOCK_MAX_ARG_DEPTH", "12"))
_MAX_VALUES = int(os.environ.get("AIRLOCK_MAX_ARG_VALUES", "4096"))
_MAX_TOTAL_CHARS = int(os.environ.get("AIRLOCK_MAX_ARG_CHARS", "1000000"))
_MAX_LEN = 8192

_SEVERITY_RANK = {"low": 0, "med": 1, "high": 2}


@dataclass
class Decision:
    action: str          # allow | ask | block  (raw rule decision)
    reason: str
    rule: int | None     # index of the matched rule, or None for default

    def combine(self, other: "Decision") -> "Decision":
        """Return the stricter of two decisions (block > ask > allow)."""
        return self if RANK[self.action] >= RANK[other.action] else other


@dataclass
class Policy:
    default: str = ASK
    ask_fallback: str = BLOCK
    rules: list[dict] = field(default_factory=list)
    mode: str = GUARD
    # minimum scan severity that escalates a decision, and to what
    escalate: dict = field(default_factory=dict)
    grants: list[dict] = field(default_factory=list)
    # provenance, for `airlock doctor` and for knowing what `allow` may edit
    path: Path | None = None
    source: str = ""
    profile: str = ""
    # Which rules can apply to a given tool name, memoised. The tool does not
    # change while the deny sweep walks hundreds of strings, but the tool glob
    # was being re-evaluated for every rule on every one of them — 636 fnmatch
    # calls per decision, most of them answering the same question again.
    _tool_index: dict = field(default_factory=dict, repr=False, compare=False)
    # A repository's own .airlock/policy.yaml. Consulted for every decision,
    # but only ever to make one stricter — see resolve().
    overlay: "Policy | None" = None
    digest: str = ""           # of the file this was loaded from

    # ---- loading -------------------------------------------------------
    @classmethod
    def resolve(cls) -> "Policy":
        """The machine's policy, with a repository's policy layered on top.

        The layer can only TIGHTEN. `.airlock/policy.yaml` used to win outright,
        which meant a cloned repository could ship four lines — `default: allow`,
        `rules: []` — and every gate on the machine went quiet: `rm -rf /`
        allowed, `~/.ssh/id_rsa` readable, the user's own paranoid profile
        superseded without a word. Cloning a repository is the most ordinary
        thing an agent does, and the file is a dotfile nobody reads.

        Teams committing a *stricter* policy to a repository still get exactly
        that, which was the feature's real purpose.
        """
        path, why, proj = config.resolve_policy_chain()
        pol = cls.load(path)
        pol.source = why
        if proj:
            try:
                over = cls.load(proj)
            except Exception as e:
                raise ValueError(f"project policy {proj}: {e}") from e
            over.source = "project"
            # A repository cannot grant itself permissions.
            over.grants = []
            pol.overlay = over
            pol.mode = _strictest_mode(pol.mode, over.mode)
            pol.default = _stricter(pol.default, over.default)
            pol.ask_fallback = _stricter(pol.ask_fallback, over.ask_fallback)
            for sev, act in (over.escalate or {}).items():
                cur = pol.escalate.get(sev)
                pol.escalate[sev] = act if cur is None else _stricter(cur, act)
        return pol

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Policy":
        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        data: dict[str, Any]
        if p.suffix in (".yaml", ".yml"):
            import yaml  # pyyaml is present; fall back to json otherwise
            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(f"{p}: policy must be a mapping, got {type(data).__name__}")
        # A file that parses to nothing is not a permissive policy — it is a
        # truncated or empty one, and under `guard` it silently allowed
        # everything, secrets included, while still looking like a valid setup.
        # Missing `rules:` is therefore a load error, which fails closed.
        if "rules" not in data:
            raise ValueError(
                f"{p}: policy has no `rules:` section — refusing to run with a "
                f"policy that enforces nothing. If you meant an empty rule list, "
                f"write `rules: []` explicitly.")
        # ${workspace} / ${home} / ${user} / ${tmp} -> real paths, so a shipped
        # policy is portable instead of being one machine's absolute paths.
        data = config.expand(data)
        pol = cls(
            default=data.get("default", ASK),
            ask_fallback=data.get("ask_fallback", BLOCK),
            rules=data.get("rules") or [],
            escalate=data.get("escalate") or {},
            grants=data.get("grants") or [],
            path=p,
            profile=data.get("profile", ""),
            digest=digest,
        )
        pol.mode = os.environ.get("AIRLOCK_MODE", data.get("mode", GUARD)).lower()
        pol.validate()
        return pol

    def has_teeth(self) -> bool:
        """Does this policy actually refuse anything?

        `rules: []` is a legitimate thing to write while building one up, so it
        loads — but nothing is being enforced, and `airlock doctor` says so
        rather than letting the install look healthy.
        """
        mine = any(r.get("action") == BLOCK for r in self.rules if isinstance(r, dict))
        return mine or bool(self.overlay and self.overlay.has_teeth())

    def validate(self) -> None:
        """Reject a malformed policy loudly — a security tool must not run on a
        file it silently half-understood."""
        for a, where in ((self.default, "default"), (self.ask_fallback, "ask_fallback")):
            if a not in RANK:
                raise ValueError(f"policy: {where} must be allow/ask/block, got {a!r}")
        for i, r in enumerate(self.rules):
            if not isinstance(r, dict):
                raise ValueError(f"policy: rule #{i} must be a mapping")
            if r.get("action", ASK) not in RANK:
                raise ValueError(f"policy: rule #{i} action must be allow/ask/block, "
                                 f"got {r.get('action')!r}")
        if self.mode not in MODES:
            raise ValueError(f"policy: mode must be one of {MODES}, got {self.mode!r}")
        for sev, act in self.escalate.items():
            if sev not in _SEVERITY_RANK or act not in RANK:
                raise ValueError(f"policy: escalate.{sev}={act!r} is not severity->action")
        for i, g in enumerate(self.grants or []):
            if not isinstance(g, dict) or not g.get("tool"):
                raise ValueError(f"policy: grant #{i} needs at least a `tool`")
            exp = g.get("expires")
            if exp is not None and not _DATE.match(str(exp)):
                raise ValueError(f"policy: grant #{i} has expires={exp!r} — "
                                 f"write YYYY-MM-DD, or leave it out")

    # ---- decision ------------------------------------------------------
    def decide(self, tool: str, args: dict | None) -> Decision:
        """Raw rule decision, tightened by the project overlay if there is one.

        `ask` is NOT collapsed here — each enforcement point resolves it
        (hook -> human prompt, proxy -> ask channel).
        """
        d = self._decide_own(tool, args)
        if self.overlay is None:
            return d
        o = self.overlay._decide_own(tool, args)
        # Only what the overlay says ON PURPOSE tightens: a rule it wrote, or a
        # refusal to read an oversized payload. Its *default* must not, because
        # the natural way to write an overlay is a couple of extra rules and
        # nothing else — and letting that default win reclassified every
        # ordinary call as `ask`. Under `paranoid` that is `block`, so adding
        # one rule to a repo stopped the agent reading its own source. A repo
        # that genuinely wants default-deny sets `default:`, which resolve()
        # already merges into the machine policy.
        if o.rule is None and o.action != BLOCK:
            return d
        if RANK[o.action] > RANK[d.action]:
            return Decision(o.action, f"{o.reason} [project policy]", o.rule)
        return d

    def _decide_own(self, tool: str, args: dict | None) -> Decision:
        args = args or {}
        primary, identified = _render(tool, args)

        # 1. absolute blocks, over the primary field and every hidden string
        hit = self._match(tool, normalize(primary), block_only=True)
        if hit is not None:
            return hit
        budget = Budget()
        seen = {primary}
        for s in iter_strings(args, budget=budget):
            if s in seen:
                continue
            seen.add(s)
            hit = self._match(tool, normalize(s), block_only=True)
            if hit is not None:
                return Decision(BLOCK,
                                f"{hit.reason} (hidden in argument: {_ellipsis(s)})",
                                hit.rule)
        if budget.exhausted:
            # We did not read all of it, so we cannot say it is clean. Refusing
            # is the only answer that keeps "a blocked string anywhere blocks"
            # true; the message says how to lift it on purpose.
            return Decision(BLOCK,
                            f"arguments too large to inspect ({budget.why}) — "
                            f"raise AIRLOCK_MAX_ARG_VALUES/CHARS to allow it",
                            None)

        # 2. reviewed grants
        g = self._match_grant(tool, normalize(primary))
        if g is not None:
            return g

        # 3. the rule list, first match wins; 4. the default
        return self._match(tool, normalize(primary), identified=identified)

    def _match_grant(self, tool: str, text: str) -> Decision | None:
        today = _today()
        for i, g in enumerate(self.grants or []):
            if not _tool_match(tool, str(g.get("tool", "*"))):
                continue
            m = g.get("match")
            if m is not None and not _glob(text, str(m).lower()):
                continue
            exp = str(g.get("expires", "") or "")
            if exp and not _expiry_ok(exp, today):
                continue          # stale, or unreadable — either way, not a grant
            who = g.get("reason") or "granted by you"
            return Decision(ALLOW, f"grant: {who}", -(i + 1))
        return None

    def _rules_for(self, tool: str) -> tuple[list, list]:
        """(all applicable rules, block-only subset) for this tool name."""
        hit = self._tool_index.get(tool)
        if hit is None:
            every, blocks = [], []
            for i, r in enumerate(self.rules):
                if not isinstance(r, dict):
                    continue
                if not _tool_match(tool, str(r.get("tool", "*"))):
                    continue
                action = r.get("action", ASK)
                entry = (i, action, _prepare(r.get("match")),
                         r.get("reason", "matched rule"))
                every.append(entry)
                if action == BLOCK:
                    blocks.append(entry)
            hit = (every, blocks)
            if len(self._tool_index) < 1024:   # bounded: tool names are attacker-set
                self._tool_index[tool] = hit
        return hit

    def _match(self, tool: str, text: str, block_only: bool = False,
               identified: bool = True):
        every, blocks = self._rules_for(tool)
        for i, action, matcher, reason in (blocks if block_only else every):
            if matcher is not None and not matcher(text):
                continue
            # A resource-scoped rule cannot vouch for a resource we could not
            # find. Tool-scoped rules (no `match`) are unaffected, and blocks
            # always stand.
            if not identified and action != BLOCK and matcher is not None:
                continue
            return Decision(action=action, reason=reason, rule=i)
        return None if block_only else Decision(self.default, "default policy", None)

    # ---- posture --------------------------------------------------------
    def posture(self, d: Decision) -> Decision:
        """Apply the mode to a raw rule decision.

        Only `observe` softens an explicit block — that is the whole point of a
        learn phase. `guard` softens the *default*, never a rule someone wrote
        down on purpose.
        """
        if self.mode == OBSERVE:
            return Decision(ALLOW, f"{d.reason} [observe]", d.rule)
        if self.mode == GUARD and d.rule is None and d.action != BLOCK:
            return Decision(ALLOW, f"{d.reason} [guard: no rule matched]", d.rule)
        return d

    def unattended_ask(self) -> str:
        """What an `ask` becomes when no human can be reached.

        enforce: fail safe (block). guard: fail quiet (allow, loudly logged) —
        otherwise `guard` would be `enforce` wearing a different hat.
        """
        return ALLOW if self.mode == GUARD else self.ask_fallback

    # ---- scan-flag escalation -----------------------------------------
    def apply_flags(self, d: Decision, flags: list[dict] | None) -> Decision:
        """Let the static scanner tighten a decision.

        `escalate: {high: ask}` in policy.yaml means "a high-severity injection
        indicator in the arguments is never silently allowed". Escalation can
        only make a decision stricter.
        """
        if not flags or not self.escalate:
            return d
        for f in flags:
            act = self.escalate.get(str(f.get("severity", "")).lower())
            if act and RANK[act] > RANK[d.action]:
                d = Decision(act, f"{d.reason} + scan flag {f.get('id')} "
                                  f"({f.get('severity')})", d.rule)
        return d


# Knobs that change nothing about what is enforced; without this the
# fingerprint would churn on every differently-invoked process.
_NOISY_KNOBS = {"AIRLOCK_QUIET", "AIRLOCK_NOTIFY", "AIRLOCK_SESSION",
                "AIRLOCK_NOTIFY_COOLDOWN", "AIRLOCK_ASK_TIMEOUT",
                "AIRLOCK_AUDIT_FSYNC", "AIRLOCK_AUDIT_MAX_MB", "AIRLOCK_LIST_WAIT"}


def gate_fingerprint(pol: "Policy") -> tuple[str, str]:
    """(fingerprint, description) of everything that decides enforcement.

    Which policy file, its contents, the mode, and the environment knobs that
    can weaken it. `AIRLOCK_POLICY=/tmp/anything` and `AIRLOCK_MODE=observe`
    each switch enforcement off outright, and the records they produce read
    exactly like ordinary ones — `rm -rf /` allowed, reason "default policy".
    The log has to be able to say that the gate it was recording was not the
    gate anybody installed.
    """
    knobs = {k: os.environ[k] for k in sorted(os.environ)
             if k.startswith("AIRLOCK_") and k not in _NOISY_KNOBS}
    parts = [str(pol.path), pol.digest, pol.mode, pol.source,
             str(getattr(pol.overlay, "path", "")),
             getattr(pol.overlay, "digest", ""),
             json.dumps(knobs, sort_keys=True)]
    fp = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    desc = f"policy={pol.path} ({pol.source}) digest={pol.digest} mode={pol.mode}"
    if pol.overlay is not None:
        desc += f" overlay={pol.overlay.path}:{pol.overlay.digest}"
    if knobs:
        desc += " env=" + ",".join(f"{k}={v}" for k, v in knobs.items())
    return fp, desc


# ---- helpers -----------------------------------------------------------
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _expiry_ok(exp: str, today: str) -> bool:
    """Is this grant still live?

    A grant is a loosening, so an expiry nobody can read has to fail towards
    refusing it. `expires: not-a-date` and `expires: 9999-99-99` both sorted
    later than today's string and therefore meant "never expires" — the exact
    inversion of what someone typing a malformed date intends.
    """
    if not _DATE.match(exp):
        return False
    try:
        y, m, d = (int(x) for x in exp.split("-"))
        if not (1 <= m <= 12 and 1 <= d <= 31):
            return False
    except ValueError:
        return False
    return exp >= today


def _stricter(a: str, b: str) -> str:
    return a if RANK.get(a, 1) >= RANK.get(b, 1) else b


_MODE_RANK = {OBSERVE: 0, GUARD: 1, ENFORCE: 2}


def _strictest_mode(a: str, b: str) -> str:
    return a if _MODE_RANK.get(a, 1) >= _MODE_RANK.get(b, 1) else b



def _tool_match(tool: str, pat: str) -> bool:
    """Case-insensitively, as the profiles say and as `match` already was.

    fnmatch is case-sensitive on POSIX, so `*fetch*` did not match `WebFetch` —
    which silently killed the shipped allow-list example for the built-in fetch
    tool, and would quietly mis-scope any rule someone wrote with a lowercase
    wildcard. Wrong in the safe direction (an un-fired allow falls through to
    ask), but wrong.
    """
    return fnmatch.fnmatch(tool.lower(), pat.lower()) or tool == pat


def _prepare(pat):
    """Compile a rule's `match` into a callable, once per rule per tool.

    Most patterns are `*literal*`, and a substring test beats a compiled regex
    by a wide margin on the long strings this runs against — a 4 KB `content`
    argument cost 1.4 ms a decision, nearly all of it regex over text that a
    single `in` answers. Semantics are unchanged: this is the same rule
    `_glob` applies, decided once instead of on every call.
    """
    if pat is None:
        return None
    p = str(pat).lower()
    core = p.strip("*")
    if not any(c in p for c in "*?[]"):
        return lambda text, c=p: c in text
    if p.startswith("*") and p.endswith("*") and not any(c in core for c in "*?[]"):
        return lambda text, c=core: c in text
    return _compiled(p)


def _compiled(p: str):
    """A callable that answers `does this text match this glob`.

    `fnmatch._compile_pattern` is private: it exists in every version we
    support and is not promised to. If it ever goes, the alternative must be a
    slower matcher, never a policy that fails to load — a security tool that
    stops enforcing because an interpreter tidied up its stdlib is worse than a
    slow one.
    """
    compile_pattern = getattr(fnmatch, "_compile_pattern", None)
    if compile_pattern is not None:
        try:
            rx = compile_pattern(p)
            return lambda text, r=rx: r(text) is not None
        except Exception:
            pass
    try:
        rx = re.compile(fnmatch.translate(p))
        return lambda text, r=rx: r.match(text) is not None
    except Exception:
        return lambda text, pat=p: fnmatch.fnmatch(text, pat)


def _glob(text: str, pat: str) -> bool:
    # a pattern with no wildcard is treated as a substring test
    if not any(c in pat for c in "*?[]"):
        return pat in text
    return fnmatch.fnmatch(text, pat)


def _today() -> str:
    import time
    return time.strftime("%Y-%m-%d", time.gmtime())


def _ellipsis(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"


@dataclass
class Budget:
    """How much of an argument object the sweep is allowed to read.

    `exhausted` is the part that matters: it tells the caller the payload was
    only partly inspected, so "no block rule matched" does not mean "clean".
    """
    values: int = _MAX_VALUES
    chars: int = _MAX_TOTAL_CHARS
    exhausted: bool = False
    why: str = ""

    def spend(self, s: str) -> bool:
        if self.values <= 0:
            self.exhausted, self.why = True, f"more than {_MAX_VALUES} values"
            return False
        if self.chars <= 0:
            self.exhausted, self.why = True, f"more than {_MAX_TOTAL_CHARS} characters"
            return False
        self.values -= 1
        self.chars -= len(s)
        return True

    def too_deep(self) -> None:
        self.exhausted, self.why = True, f"nested deeper than {_MAX_DEPTH}"


def iter_strings(obj: Any, _depth: int = 0, budget: "Budget | None" = None
                 ) -> Iterator[str]:
    """Yield every string reachable in a JSON-ish structure — values AND keys.

    Keys count because an attacker controls the whole argument object, and a
    tool that iterates its own kwargs can act on a key just as easily.
    """
    if budget is None:
        budget = Budget()
    if budget.exhausted:
        return
    if _depth > _MAX_DEPTH:
        budget.too_deep()
        return
    if isinstance(obj, str):
        if budget.spend(obj):
            yield obj[:_MAX_LEN]
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and budget.spend(k):
                yield k[:_MAX_LEN]
            yield from iter_strings(v, _depth + 1, budget)
            if budget.exhausted:
                return
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v, _depth + 1, budget)
            if budget.exhausted:
                return


# per-tool "action string": the single most security-relevant field, so that
# `match` globs read naturally ("rm -rf*", "*/.ssh/*", "http://169.254.*").
_FIELD = {
    "bash": ("command",),
    "shell": ("command", "cmd"),
    "run_command": ("command", "cmd"),
    "execute": ("command", "cmd", "code"),
    "read": ("file_path", "path"),
    "read_file": ("path", "file_path"),
    "read_text_file": ("path", "file_path"),
    "read_note": ("name", "path"),
    "write": ("file_path", "path", "content"),
    "write_file": ("path", "file_path"),
    "edit": ("file_path", "path"),
    "webfetch": ("url",),
    "fetch_url": ("url",),
    "fetch": ("url",),
    "resources_read": ("uri",),
    "glob": ("pattern", "path"),
    "grep": ("pattern", "path"),
}


_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_MAX_DECODE = 64        # each round strictly shrinks the string, so this is a
                        # runaway guard, not a statement about how deep is legal


def normalize(text: str) -> str:
    """Fold the spellings that mean the same path down to one, for matching.

    Rules are string matches, so `~/%2essh/config` and a fullwidth `~/．ssh/`
    sailed straight past `*/.ssh/*` while still naming that directory to
    anything which percent-decodes a URI or normalises Unicode. Decoded twice,
    because `%252e` is how you get a `%2e` past one round of decoding.

    A matching aid only: it never changes what gets passed on. A tool that does
    NOT decode simply sees a rule fire on a path it would not have opened,
    which is the safe direction to be wrong in.
    """
    # Fast path: the overwhelming majority of arguments are plain ASCII with
    # nothing to fold, and this runs on every string in the deny sweep.
    if text.isascii() and "%" not in text and "\\" not in text:
        return text.lower()
    out = unicodedata.normalize("NFKC", text)
    # Decode to a FIXPOINT, not a fixed number of rounds. Two rounds handled
    # `%252e`; `%25252e` needed three, and stopping early left `/x/%2essh/`
    # looking like an ordinary path. The bound is a runaway guard, not a
    # policy: sixty-four levels of nesting is not a path anyone typed.
    for _ in range(_MAX_DECODE):
        if "%" not in out:
            break
        try:
            dec = unicodedata.normalize(
                "NFKC", _PCT.sub(lambda m: chr(int(m.group(0)[1:], 16)), out))
        except Exception:
            break
        if dec == out:
            break
        out = dec
    return out.replace("\\", "/").lower()


def render_action(tool: str, args: dict) -> str:
    return _render(tool, args)[0]


def _render(tool: str, args: dict) -> tuple[str, bool]:
    """(text, was the resource actually identified).

    False means no known field held it and this is the whole argument blob
    instead. A `match` glob then tests text that includes every other
    argument, so an unrelated one can satisfy it. Harmless for a block rule —
    the deny sweep reads every string anyway — and not harmless for an allow
    rule, which would be certifying a resource nobody could name.
    """
    key = tool.lower().split("__")[-1]  # mcp__srv__fetch_url -> fetch_url
    for f in _FIELD.get(key, ()):
        if f in args and isinstance(args[f], str):
            return args[f], True
    # Generic: flatten args to a searchable blob, capped. Uncapped, a 20k-key
    # payload produced a 4 MB string and every glob in the rule list was matched
    # against all of it — 2.8 s inside the gate, from one tool call. Every
    # individual string is inspected separately by the deny sweep anyway.
    try:
        return json.dumps(args, ensure_ascii=False)[:_MAX_LEN], False
    except Exception:
        return str(args)[:_MAX_LEN], False
