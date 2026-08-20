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
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import config

ALLOW, ASK, BLOCK = "allow", "ask", "block"
OBSERVE, GUARD, ENFORCE = "observe", "guard", "enforce"
MODES = (OBSERVE, GUARD, ENFORCE)

# strictness ordering: block is strictest, allow is loosest
RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}

# bounds for the deny sweep, so a pathological payload can't burn the hot path
_MAX_DEPTH = 8
_MAX_VALUES = 512
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

    # ---- loading -------------------------------------------------------
    @classmethod
    def resolve(cls) -> "Policy":
        """Load whichever policy applies here: env, then project, then user,
        then the bundled profile."""
        path, why = config.resolve_policy()
        pol = cls.load(path)
        pol.source = why
        return pol

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Policy":
        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        data: dict[str, Any]
        if p.suffix in (".yaml", ".yml"):
            import yaml  # pyyaml is present; fall back to json otherwise
            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(f"{p}: policy must be a mapping, got {type(data).__name__}")
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
        )
        pol.mode = os.environ.get("AIRLOCK_MODE", data.get("mode", GUARD)).lower()
        pol.validate()
        return pol

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

    # ---- decision ------------------------------------------------------
    def decide(self, tool: str, args: dict | None) -> Decision:
        """Raw rule decision. `ask` is NOT collapsed here — each enforcement
        point resolves it (hook -> human prompt, proxy -> ask channel)."""
        args = args or {}
        primary = render_action(tool, args)

        # 1. absolute blocks, over the primary field and every hidden string
        hit = self._match(tool, primary.lower(), block_only=True)
        if hit is not None:
            return hit
        seen = {primary}
        for s in iter_strings(args):
            if s in seen:
                continue
            seen.add(s)
            hit = self._match(tool, s.lower(), block_only=True)
            if hit is not None:
                return Decision(BLOCK,
                                f"{hit.reason} (hidden in argument: {_ellipsis(s)})",
                                hit.rule)

        # 2. reviewed grants
        g = self._match_grant(tool, primary.lower())
        if g is not None:
            return g

        # 3. the rule list, first match wins; 4. the default
        return self._match(tool, primary.lower())

    def _match_grant(self, tool: str, text: str) -> Decision | None:
        today = _today()
        for i, g in enumerate(self.grants or []):
            if not _tool_match(tool, str(g.get("tool", "*"))):
                continue
            m = g.get("match")
            if m is not None and not _glob(text, str(m).lower()):
                continue
            exp = str(g.get("expires", "") or "")
            if exp and exp < today:
                continue          # a stale grant is not a grant
            who = g.get("reason") or "granted by you"
            return Decision(ALLOW, f"grant: {who}", -(i + 1))
        return None

    def _match(self, tool: str, text: str, block_only: bool = False):
        for i, r in enumerate(self.rules):
            action = r.get("action", ASK)
            if block_only and action != BLOCK:
                continue
            if not _tool_match(tool, r.get("tool", "*")):
                continue
            m = r.get("match")
            if m is not None and not _glob(text, str(m).lower()):
                continue
            return Decision(action=action, reason=r.get("reason", "matched rule"), rule=i)
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


# ---- helpers -----------------------------------------------------------
def _tool_match(tool: str, pat: str) -> bool:
    """Case-insensitively, as the profiles say and as `match` already was.

    fnmatch is case-sensitive on POSIX, so `*fetch*` did not match `WebFetch` —
    which silently killed the shipped allow-list example for the built-in fetch
    tool, and would quietly mis-scope any rule someone wrote with a lowercase
    wildcard. Wrong in the safe direction (an un-fired allow falls through to
    ask), but wrong.
    """
    return fnmatch.fnmatch(tool.lower(), pat.lower()) or tool == pat


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


def iter_strings(obj: Any, _depth: int = 0, _budget: list | None = None) -> Iterator[str]:
    """Yield every string reachable in a JSON-ish structure — values AND keys.

    Keys count because an attacker controls the whole argument object, and a
    tool that iterates its own kwargs can act on a key just as easily.
    """
    if _budget is None:
        _budget = [_MAX_VALUES]
    if _depth > _MAX_DEPTH or _budget[0] <= 0:
        return
    if isinstance(obj, str):
        _budget[0] -= 1
        yield obj[:_MAX_LEN]
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                _budget[0] -= 1
                yield k[:_MAX_LEN]
            yield from iter_strings(v, _depth + 1, _budget)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v, _depth + 1, _budget)


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


def render_action(tool: str, args: dict) -> str:
    key = tool.lower().split("__")[-1]  # mcp__srv__fetch_url -> fetch_url
    for f in _FIELD.get(key, ()):
        if f in args and isinstance(args[f], str):
            return args[f]
    # generic: flatten args to a searchable blob
    try:
        return json.dumps(args, ensure_ascii=False)
    except Exception:
        return str(args)
