"""`airlock report` — the artifact someone shows their manager.

Security that works is invisible. A tool that spent a week quietly gating an
agent and produced nothing to look at gets judged useless and removed. So the
week has to end in a page: how much was gated, what was refused, which servers
are asking for more than they were granted, and how often a human was pulled in.

The over-privilege section is the one that changes behaviour: it compares what a
server was granted against what it actually used, and proposes the tighter
contract. That is the observe->enforce loop, made legible.
"""
from __future__ import annotations
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import audit, config


def _parse_ts(ts: str) -> float:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(ts, fmt))
        except Exception:
            continue
    return 0.0


@dataclass
class Report:
    since: str = ""
    until: str = ""
    days: int = 7
    total: int = 0
    by_effect: Counter = field(default_factory=Counter)
    by_source: Counter = field(default_factory=Counter)
    blocked_reasons: Counter = field(default_factory=Counter)
    blocked_tools: Counter = field(default_factory=Counter)
    asked: int = 0
    ask_to_agent: int = 0      # handed to the agent's own approval prompt (hook)
    ask_answered: int = 0      # a human answered a dialog (proxy + ask channel)
    ask_unattended: int = 0    # nobody was there; resolved by the mode
    ask_to_block: int = 0      # an ask that the scanner or a contract escalated
    ask_to_allow: int = 0      # an ask the mode resolved without anyone present
    scan_flags: Counter = field(default_factory=Counter)
    servers: dict = field(default_factory=dict)
    held: list = field(default_factory=list)
    overprivileged: list = field(default_factory=list)
    chain_ok: bool = True
    chain_msg: str = ""
    quiet_days: int = 0

    def to_dict(self) -> dict:
        return {
            "window": {"since": self.since, "until": self.until, "days": self.days},
            "totals": {"decisions": self.total, **dict(self.by_effect)},
            "by_source": dict(self.by_source),
            "blocked": {"reasons": self.blocked_reasons.most_common(),
                        "tools": self.blocked_tools.most_common()},
            "human": {"asked": self.asked, "to_agent_prompt": self.ask_to_agent,
                  "answered_by_you": self.ask_answered,
                  "unattended": self.ask_unattended,
                  "escalated_to_block": self.ask_to_block,
                  "allowed_unattended": self.ask_to_allow},
            "scan_flags": self.scan_flags.most_common(),
            "servers": self.servers,
            "held": self.held,
            "overprivileged": self.overprivileged,
            "audit_chain": {"ok": self.chain_ok, "detail": self.chain_msg},
        }


def _contracts() -> dict:
    p = config.home() / "contracts.yaml"
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def build(days: int = 7, path: Path | None = None) -> Report:
    r = Report(days=days)
    cutoff = time.time() - days * 86400
    p = path or audit.audit_path()
    r.until = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
    if not p.exists():
        r.chain_msg = "no audit log yet"
        return r

    per_server = defaultdict(lambda: Counter())
    first_ts = None
    seen_days = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        ts = _parse_ts(rec.get("ts", ""))
        if ts and ts < cutoff:
            continue
        if first_ts is None and ts:
            first_ts = ts
        if rec.get("ts"):
            seen_days.add(rec["ts"][:10])

        ev = rec.get("event")
        if ev == "decision":
            r.total += 1
            eff = rec.get("effective") or "?"
            r.by_effect[eff] += 1
            r.by_source[rec.get("source") or "?"] += 1
            srv = rec.get("server") or rec.get("source") or "-"
            per_server[srv][eff] += 1
            if rec.get("decision") == "ask":
                r.asked += 1
                if eff == "block":
                    r.ask_to_block += 1
                elif eff == "allow":
                    r.ask_to_allow += 1
                reason = rec.get("reason") or ""
                if rec.get("source") == "hook" and eff == "ask":
                    r.ask_to_agent += 1
                elif "[ask:fallback]" in reason:
                    r.ask_unattended += 1
                elif "[ask:" in reason:
                    r.ask_answered += 1
                else:
                    r.ask_unattended += 1
            if eff == "block":
                r.blocked_reasons[rec.get("reason", "?").split(" (")[0]] += 1
                r.blocked_tools[rec.get("tool", "?")] += 1
        elif ev == "scan_flag":
            r.scan_flags[rec.get("reason", "?")] += 1
        elif ev in ("toolset_changed", "toolset_held"):
            srv = rec.get("server")
            if srv and srv not in r.held:
                r.held.append(srv)

    r.since = time.strftime("%Y-%m-%d %H:%M", time.gmtime(first_ts)) if first_ts \
        else r.until
    r.quiet_days = max(0, days - len(seen_days))
    r.servers = {k: dict(v) for k, v in sorted(per_server.items())}
    r.chain_ok, _n, r.chain_msg = audit.verify(p)

    # over-privilege: granted vs actually used
    for sid, c in _contracts().items():
        obs = c.get("_observed") or {}
        if not obs and not c.get("enforced"):
            continue
        granted_tools = set(c.get("tools") or [])
        used_tools = set(obs.get("tools") or [])
        unused = sorted(granted_tools - used_tools)
        extras = []
        if c.get("shell") and not obs.get("shell"):
            extras.append("shell (never used)")
        if c.get("net") and not obs.get("net"):
            extras.append(f"{len(c['net'])} egress host(s) (never used)")
        if unused or extras:
            r.overprivileged.append({
                "server": sid,
                "enforced": bool(c.get("enforced")),
                "unused_tools": unused,
                "unused_capabilities": extras,
                "used_tools": sorted(used_tools),
            })
    return r


# ---- rendering ---------------------------------------------------------
_C = {"h": "\033[31m", "m": "\033[33m", "l": "\033[32m", "b": "\033[1m",
      "d": "\033[2m", "c": "\033[36m", "0": "\033[0m"}


def render(r: Report, *, color: bool = True) -> str:
    c = _C if color else {k: "" for k in _C}
    o: list[str] = []
    o.append(f"\n{c['b']}AIRLOCK REPORT{c['0']}  {c['d']}{r.since} → {r.until} UTC "
             f"({r.days}d window){c['0']}\n")

    if r.total == 0:
        o.append(f"  {c['d']}No gated calls in this window. Either the agents were "
                 f"idle, or Airlock is not wired in — check `airlock doctor`.{c['0']}\n")
        return "\n".join(o)

    allowed = r.by_effect.get("allow", 0)
    blocked = r.by_effect.get("block", 0)
    asked = r.by_effect.get("ask", 0)
    pct = lambda n: f"{100 * n / r.total:.1f}%"
    o.append(f"  {c['b']}{r.total}{c['0']} calls gated · "
             f"{c['l']}{allowed} allowed{c['0']} ({pct(allowed)}) · "
             f"{c['h']}{blocked} blocked{c['0']} ({pct(blocked)}) · "
             f"{c['m']}{asked} asked{c['0']} ({pct(asked)})")
    src = ", ".join(f"{k}={v}" for k, v in sorted(r.by_source.items()))
    # Say what actually happened to the asks that did not stay asks. Reporting
    # them all as "escalated to a block" over-claimed protection in guard mode,
    # where they were allowed.
    if r.ask_to_block:
        src += f" · {r.ask_to_block} ask(s) escalated to a block"
    if r.ask_to_allow:
        src += f" · {r.ask_to_allow} ask(s) allowed with nobody present"
    o.append(f"  {c['d']}sources: {src}{c['0']}\n")

    if blocked:
        o.append(f"  {c['b']}What was refused{c['0']}")
        for reason, n in r.blocked_reasons.most_common(8):
            o.append(f"    {c['h']}{n:4}{c['0']}  {reason}")
        o.append("")
        o.append(f"  {c['b']}Which tools tried{c['0']}")
        for tool, n in r.blocked_tools.most_common(5):
            o.append(f"    {c['h']}{n:4}{c['0']}  {tool}")
        o.append("")

    if r.held:
        o.append(f"  {c['b']}Servers held for review{c['0']}  "
                 f"{c['d']}(toolset changed since it was pinned){c['0']}")
        for s in r.held:
            o.append(f"    {c['h']}HELD{c['0']}  {s}    {c['d']}airlock pins approve {s}{c['0']}")
        o.append("")

    if r.overprivileged:
        o.append(f"  {c['b']}Servers asking for more than they use{c['0']}")
        for e in r.overprivileged:
            state = "enforced" if e["enforced"] else "proposal"
            o.append(f"    {c['c']}{e['server']}{c['0']} {c['d']}({state}){c['0']}")
            if e["unused_tools"]:
                o.append(f"      {c['m']}unused tools:{c['0']} "
                         f"{', '.join(e['unused_tools'][:8])}")
            for x in e["unused_capabilities"]:
                o.append(f"      {c['m']}unused:{c['0']} {x}")
            o.append(f"      {c['d']}tighten: airlock contracts promote {e['server']}{c['0']}")
        o.append("")

    if r.scan_flags:
        o.append(f"  {c['b']}Static indicators seen{c['0']}")
        for flag, n in r.scan_flags.most_common(6):
            o.append(f"    {c['m']}{n:4}{c['0']}  {flag}")
        o.append("")

    o.append(f"  {c['b']}Human involvement{c['0']}")
    if r.asked:
        parts = []
        if r.ask_to_agent:
            parts.append(f"{r.ask_to_agent} via your agent's own prompt")
        if r.ask_answered:
            parts.append(f"{r.ask_answered} you answered directly")
        if r.ask_unattended:
            how = ("allowed" if r.ask_to_allow >= r.ask_to_block else "refused")
            parts.append(f"{r.ask_unattended} resolved unattended ({how})")
        o.append(f"    {r.asked} call(s) needed a decision — " + ", ".join(parts))
        o.append(f"    {c['d']}~{r.asked / max(1, r.days):.1f} interruptions per day"
                 f"{c['0']}")
        if r.ask_unattended:
            o.append(f"    {c['m']}·{c['0']} {r.ask_unattended} resolved with nobody "
                     f"there — run `airlock askd` to be asked for real")
    else:
        o.append(f"    {c['l']}never interrupted you{c['0']}")
    o.append("")

    tone = c["l"] if r.chain_ok else c["h"]
    o.append(f"  {c['b']}Audit{c['0']}  {tone}"
             f"{'chain intact' if r.chain_ok else 'CHAIN BROKEN'}{c['0']} "
             f"{c['d']}— {r.chain_msg}{c['0']}")
    o.append(f"  {c['d']}{audit.audit_path()}{c['0']}\n")
    return "\n".join(o)


def render_markdown(r: Report) -> str:
    """For pasting into a ticket, a wiki, or a message to your manager."""
    d = r.to_dict()
    o = [f"# Airlock report — {r.since} → {r.until} UTC ({r.days}d)", ""]
    if r.total == 0:
        o.append("No gated calls in this window.")
        return "\n".join(o)
    t = d["totals"]
    o += [f"**{r.total} agent calls gated.** "
          f"{t.get('allow', 0)} allowed, {t.get('block', 0)} blocked, "
          f"{t.get('ask', 0)} sent to a human.", ""]
    if r.blocked_reasons:
        o += ["## What was refused", "", "| count | reason |", "|---|---|"]
        o += [f"| {n} | {why} |" for why, n in r.blocked_reasons.most_common(10)]
        o.append("")
    if r.held:
        o += ["## Held for review", ""]
        o += [f"- `{s}` — toolset changed since it was pinned" for s in r.held]
        o.append("")
    if r.overprivileged:
        o += ["## Over-privileged servers", ""]
        for e in r.overprivileged:
            bits = []
            if e["unused_tools"]:
                bits.append(f"never used: {', '.join(e['unused_tools'][:8])}")
            bits += e["unused_capabilities"]
            o.append(f"- `{e['server']}` — {'; '.join(bits)}")
        o.append("")
    o += ["## Human involvement", "",
          f"- {r.asked} call(s) needed a decision over {r.days} days "
          f"(~{r.asked / max(1, r.days):.1f}/day)",
          f"- {r.ask_to_agent} handed to the agent's approval prompt, "
          f"{r.ask_answered} answered directly, {r.ask_unattended} unattended",
          f"- audit chain: {'intact' if r.chain_ok else 'BROKEN — ' + r.chain_msg}", ""]
    return "\n".join(o)
