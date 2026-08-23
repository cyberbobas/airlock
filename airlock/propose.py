"""`airlock policy propose` — least privilege, derived from what actually happened.

`airlock allow` grants the one thing you were just stopped on. This is its bulk
cousin, for onboarding: run a week in `yolo` (or `observe`), then read the whole
audit log back and emit the narrowest set of allows that still covers everything
your agents actually did. The firewall watches, then writes its own policy.

The rule that makes this safe: propose only ALLOW rules, only for calls that were
actually allowed and carried no high-severity scan flag. A call that was blocked,
asked about, or flagged for reaching a secret or a collector is reported so you
can see it — never silently whitelisted. Absolute blocks stay absolute; a
proposed grant can no more lift them than a hand-written one can.
"""
from __future__ import annotations
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import audit, contracts, grants as grantmod
from .policy import normalize


@dataclass
class Proposal:
    days: int
    grants: list[dict] = field(default_factory=list)
    allowed: int = 0                       # allowed calls that fed a grant
    gated: Counter = field(default_factory=Counter)   # tool -> asked/blocked count
    risky: Counter = field(default_factory=Counter)   # tool -> high-flag count
    tools: Counter = field(default_factory=Counter)   # tool -> total allowed
    truncated: int = 0                     # grants dropped by the per-tool cap
    unscopable: Counter = field(default_factory=Counter)  # tool -> calls we could
    #                                        not turn into a match (no path/host)


_MAX_MATCHES_PER_TOOL = 20                  # a tool touching 500 files gets a note,
#                                            not 500 grants — the point is a policy


def _bucket(tool: str, resource: str) -> tuple[str, str] | None:
    """Classify one audit `resource` into (kind, value) for scoping.

    The audit already stores the single most security-relevant field per call —
    a path, a host, or a command — so we bucket that rather than re-deriving it.
    """
    res = (resource or "").strip()
    base = tool.lower().split("__")[-1]
    if not res:
        return None
    host = contracts._url_host(res)
    if host:
        return ("net", host.lower())
    if contracts._looks_like_path(res):
        return ("fs", os.path.normpath(os.path.expanduser(normalize(res))))
    if base in contracts._SHELL_TOOLS:
        return ("shell", res)
    return None


def build(days: int = 30, *, min_count: int = 1, path=None) -> Proposal:
    """Read the audit log and synthesise the tightest allow set that covers it."""
    prop = Proposal(days=days)
    p = path or audit.audit_path()
    if not p.exists():
        return prop
    cutoff = time.time() - days * 86400

    fs_by_tool: dict[str, set] = defaultdict(set)
    net_by_tool: dict[str, set] = defaultdict(set)
    shell_tools: set = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("event") != "decision":
            continue
        ts = rec.get("ts", "")
        try:
            if ts and time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) < cutoff:
                continue
        except Exception:
            pass
        tool = rec.get("tool") or ""
        if not tool:
            continue
        eff = rec.get("effective") or ""
        if eff != "allow":
            prop.gated[tool] += 1
            continue
        if any((f or {}).get("severity") == "high" for f in rec.get("flags") or []):
            prop.risky[tool] += 1
            continue
        prop.tools[tool] += 1
        b = _bucket(tool, rec.get("resource") or "")
        if b is None:
            prop.unscopable[tool] += 1
            continue
        kind, value = b
        if kind == "fs":
            fs_by_tool[tool].add(value)
        elif kind == "net":
            net_by_tool[tool].add(value)
        else:
            shell_tools.add(tool)

    prop.allowed = sum(prop.tools.values())
    stamp = time.strftime("%Y-%m-%d")

    def emit(tool: str, match: str | None, why: str) -> None:
        g = {"tool": tool, "action": "allow"}
        if match:
            g["match"] = match
        g["reason"] = f"proposed from {prop.allowed_label()} on {stamp} ({why})"
        prop.grants.append(g)

    for tool in sorted(set(fs_by_tool) | set(net_by_tool) | shell_tools):
        if prop.tools[tool] < min_count:
            continue
        matches: list[tuple[str | None, str]] = []
        for glob in sorted(contracts._generalize(fs_by_tool.get(tool, set()))):
            matches.append((glob, "observed file access"))
        for host in sorted(net_by_tool.get(tool, set())):
            matches.append((f"*{host}*", "observed egress host"))
        if tool in shell_tools:
            matches.append((None, "observed shell use — REVIEW before enforcing"))
        if len(matches) > _MAX_MATCHES_PER_TOOL:
            prop.truncated += len(matches) - _MAX_MATCHES_PER_TOOL
            matches = matches[:_MAX_MATCHES_PER_TOOL]
        for match, why in matches:
            emit(tool, match, why)

    return prop


# small helper so the reason line reads naturally without threading the count in
def _allowed_label(self: Proposal) -> str:
    return f"{self.allowed} allowed call{'' if self.allowed == 1 else 's'}"


Proposal.allowed_label = _allowed_label  # type: ignore[attr-defined]


def to_yaml(prop: Proposal) -> str:
    import yaml
    banner = (
        f"# Proposed by `airlock policy propose` on {time.strftime('%Y-%m-%d')}.\n"
        f"# Derived from {prop.allowed} allowed calls over the last {prop.days} days.\n"
        f"# These are the narrowest allows that cover what your agents already did.\n"
        f"# Review, then either `airlock policy propose --apply` or paste into grants:.\n"
        f"# Switch to a guarding profile to make them bite: airlock profile default\n")
    body = yaml.safe_dump({"grants": prop.grants}, sort_keys=False, allow_unicode=True)
    return banner + body


def apply(pol, prop: Proposal, *, include_shell: bool = False) -> tuple[int, int, int]:
    """Append proposed grants to the active policy. Returns (added, skipped, held).

    A shell grant carries no `match` — it allows a shell tool outright, which is
    the broadest thing propose can suggest. Absolute blocks (`rm -rf /`,
    `curl | sh`, …) still can't be lifted by it, but `npm test` and every other
    ordinary shell call would become allow-without-ask. That is too sharp to
    write unattended, so `apply` HOLDS shell grants back by default and reports
    them; pass include_shell=True to write them too.
    """
    added = skipped = held = 0
    for g in prop.grants:
        if "match" not in g and not include_shell:      # a bare shell grant
            held += 1
            continue
        _, msg = grantmod.add(pol, dict(g))
        if msg == "granted":
            added += 1
        else:
            skipped += 1
    return added, skipped, held
