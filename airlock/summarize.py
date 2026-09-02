"""`airlock summary` — what did the agent actually do this session?

Not everyone reads a JSONL audit log, and not everyone should have to. This turns
the log into an answer: how many calls, what was blocked, what was touched, what
to check. Two layers, and the first never needs a model:

  1. Structured facts computed with pure Python (counts, blocks, flags, targets).
     This alone is the `lite` output and the always-available fallback.
  2. If an AI backend is available (standard/pro), a short plain-language
     narrative on top. Facts are redacted before they ever reach a model.

The log already stores no raw arguments (only an `args_digest`), so there is
little to leak here — but we redact resources/reasons before any model call
anyway, because the whole product is about not handing secrets to models.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from . import audit
from .ai import get_backend
from .ai.prompts import redact_obj

_GATED = ("block", "ask")
_MAX_LIST = 20
_TOP = 15


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _read_events(days: float | None, session: str) -> list[dict]:
    """Audit records across rotated segments, filtered by window / session."""
    cutoff = None
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out: list[dict] = []
    for p in audit.rotated_files():
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if session and r.get("session") != session:
                continue
            if cutoff is not None:
                t = _parse_ts(r.get("ts", ""))
                if t is not None and t < cutoff:
                    continue
            out.append(r)
    return out


@dataclass
class Facts:
    """Everything the summary knows, computed without a model."""
    window: dict = field(default_factory=dict)
    totals: dict = field(default_factory=dict)
    top_tools: list = field(default_factory=list)
    servers: list = field(default_factory=list)
    blocked: list = field(default_factory=list)
    asked: list = field(default_factory=list)
    scan_flags: dict = field(default_factory=dict)
    resources_touched: list = field(default_factory=list)
    sessions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def build_facts(days: float | None = 1.0, session: str = "") -> Facts:
    ev = _read_events(days, session)
    decisions = [r for r in ev if r.get("event") == "decision"]
    outcomes = [r for r in ev if r.get("event") == "outcome"]

    eff = Counter(r.get("effective") or r.get("decision") or "?" for r in decisions)
    tools = Counter(r.get("tool", "") for r in decisions if r.get("tool"))
    servers = Counter(r.get("server", "") for r in decisions if r.get("server"))
    resources = Counter(
        r.get("resource", "") for r in decisions
        if r.get("resource") and r.get("effective") in ("allow", "ran")
    )

    def _rows(kind: str) -> list[dict]:
        seen, rows = set(), []
        for r in decisions:
            if r.get("effective") != kind:
                continue
            key = (r.get("tool"), r.get("resource"))
            if key in seen:
                continue
            seen.add(key)
            rows.append({"tool": r.get("tool", ""), "resource": r.get("resource", ""),
                         "reason": r.get("reason", "")})
            if len(rows) >= _MAX_LIST:
                break
        return rows

    sev = Counter()
    n_flags = 0
    for r in decisions:
        for fl in (r.get("flags") or []):
            n_flags += 1
            if isinstance(fl, dict):
                sev[fl.get("severity", "?")] += 1

    ts_all = [t for t in (_parse_ts(r.get("ts", "")) for r in ev) if t]
    sessions = sorted({r.get("session", "") for r in ev if r.get("session")})

    return Facts(
        window={
            "days": days, "session": session or None,
            "from": min(ts_all).isoformat() if ts_all else None,
            "to": max(ts_all).isoformat() if ts_all else None,
        },
        totals={
            "events": len(ev),
            "decisions": len(decisions),
            "allowed": eff.get("allow", 0),
            "asked": eff.get("ask", 0),
            "blocked": eff.get("block", 0),
            "ran": sum(1 for r in outcomes if r.get("effective") == "ran"),
        },
        top_tools=tools.most_common(_TOP),
        servers=servers.most_common(_TOP),
        blocked=_rows("block"),
        asked=_rows("ask"),
        scan_flags={"total": n_flags, "by_severity": dict(sev)},
        resources_touched=resources.most_common(_TOP),
        sessions=sessions,
    )


def narrate(facts: Facts, cfg=None) -> str:
    """Plain-language narrative from a model, or "" if no backend is available."""
    backend = get_backend(cfg)
    if not backend.available():
        return ""
    try:
        return backend.summarize(redact_obj(facts.to_dict())).strip()
    except Exception:
        return ""


def summarize(days: float | None = 1.0, session: str = "", cfg=None) -> tuple[Facts, str]:
    facts = build_facts(days, session)
    return facts, narrate(facts, cfg)


# --- rendering --------------------------------------------------------------

def render(facts: Facts, narrative: str = "", color: bool = False) -> str:
    t = facts.totals
    if not t.get("events"):
        return ("airlock summary: no activity recorded yet.\n"
                "Once the agent runs under the proxy or hook, its calls land here.")
    L: list[str] = []
    if narrative:
        L += [narrative, ""]
    win = facts.window
    span = ""
    if win.get("from") and win.get("to"):
        span = f"  ({win['from'][:16]} .. {win['to'][:16]})"
    L.append(f"airlock summary{span}")
    L.append(f"  {t['decisions']} decisions  ·  {t['allowed']} allowed  ·  "
             f"{t['asked']} asked  ·  {t['blocked']} blocked")
    sf = facts.scan_flags
    if sf.get("total"):
        by = ", ".join(f"{k}:{v}" for k, v in sf["by_severity"].items())
        L.append(f"  scan flags: {sf['total']} ({by})")
    if facts.blocked:
        L.append("")
        L.append(f"BLOCKED ({len(facts.blocked)})")
        for r in facts.blocked:
            tgt = f"  {r['resource']}" if r["resource"] else ""
            L.append(f"  ✗ {r['tool']}{tgt}")
            if r["reason"]:
                L.append(f"      {r['reason']}")
    if facts.asked:
        L.append("")
        L.append(f"ASKED ({len(facts.asked)})")
        for r in facts.asked:
            tgt = f"  {r['resource']}" if r["resource"] else ""
            L.append(f"  ? {r['tool']}{tgt}")
    if facts.top_tools:
        L.append("")
        L.append("TOP TOOLS")
        for tool, n in facts.top_tools[:8]:
            L.append(f"  {n:>4}  {tool}")
    if facts.resources_touched:
        L.append("")
        L.append("TOUCHED")
        for res, n in facts.resources_touched[:8]:
            L.append(f"  {n:>4}  {res}")
    return "\n".join(L)


def render_markdown(facts: Facts, narrative: str = "") -> str:
    t = facts.totals
    if not t.get("events"):
        return "## airlock summary\n\n_No activity recorded yet._"
    L = ["## airlock summary", ""]
    if narrative:
        L += [narrative, ""]
    L.append(f"**{t['decisions']}** decisions — {t['allowed']} allowed, "
             f"{t['asked']} asked, **{t['blocked']} blocked**.")
    if facts.scan_flags.get("total"):
        L.append(f"Scan flags: {facts.scan_flags['total']}.")
    if facts.blocked:
        L += ["", "### Blocked", ""]
        for r in facts.blocked:
            tgt = f" `{r['resource']}`" if r["resource"] else ""
            L.append(f"- **{r['tool']}**{tgt}" + (f" — {r['reason']}" if r["reason"] else ""))
    if facts.asked:
        L += ["", "### Asked", ""]
        for r in facts.asked:
            tgt = f" `{r['resource']}`" if r["resource"] else ""
            L.append(f"- {r['tool']}{tgt}")
    return "\n".join(L)
