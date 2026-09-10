"""Scheduled audit review — read the journal over a window and flag trouble.

`airlock summary` recaps ONE session for a human. This is the security-analyst
counterpart: look across a time window (6h / a day / a week / a month), compute
deterministic suspicion signals, and — if an AI backend is available (the
built-in micro-brain or a bring-your-own big model) — add an analyst verdict.
The report is saved under $AIRLOCK_HOME/reports/ so a scheduled run leaves a
trail even when nobody is watching.

The deterministic layer is the floor: the signals below are computed with pure
Python and are always right. The model only ever *adds* narrative and a triage
verdict on top; if it is slow, absent, or off-task it is dropped and the
structured report stands (same fail-safe posture as the judge and summary).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from . import audit
from .ai import get_backend
from .ai.prompts import redact_obj
from .summarize import _parse_ts, _read_events, build_facts

# Windows we name; anything else is raw hours. (label -> hours)
WINDOWS = {"6h": 6.0, "day": 24.0, "daily": 24.0, "week": 168.0, "weekly": 168.0,
           "month": 720.0, "monthly": 720.0}

# Block-reason / resource classification. Each category is a (name, regex); the
# first match wins. These mirror the profile's absolute-block families, so a
# report groups blocks the way the policy thinks about them.
_CATEGORIES = [
    ("secret_read", re.compile(
        r"secret|credential|\.env|\.ssh|id_rsa|id_ed25519|\.aws|kube|password|"
        r"token|keychain|keyring|\.netrc|shadow|/proc/\d+/environ|history", re.I)),
    ("exfiltration", re.compile(
        r"exfil|webhook\.site|pastebin|transfer\.sh|0x0\.st|requestbin|oastify|"
        r"outside host|nc |ncat |curl.*(-F|-T|--data|-d @)|\| *nc", re.I)),
    ("reverse_shell", re.compile(
        r"reverse shell|/dev/tcp/|bash -i|pty\.spawn|mkfifo", re.I)),
    ("log_erasure", re.compile(
        r"log|audit|journalctl|--vacuum|dmesg|auditctl|erase|wipe|shred|truncate",
        re.I)),
    ("cloud_metadata_ssrf", re.compile(
        r"metadata|169\.254\.169\.254|ssrf|2852039166|0xa9fea9fe", re.I)),
    ("destructive", re.compile(
        r"destructive|rm -rf|mkfs|drop (table|database)|flushall|terraform destroy|"
        r"delete (namespace|bucket|repo)|irreversible|force-push", re.I)),
    ("download_execute", re.compile(
        r"pipe-to-|curl-pipe|download-and-execute|untrusted source|install.*http", re.I)),
    ("gate_tamper", re.compile(
        r"gate|airlock|mcp server list|rewire|its own firewall|fail.?open|"
        r"AIRLOCK_", re.I)),
]

# Categories that make a window suspicious on their own (an attacker's toolkit).
_ALARMING = {"secret_read", "exfiltration", "reverse_shell", "log_erasure",
             "cloud_metadata_ssrf", "gate_tamper"}

_BURST_WINDOW_S = 300      # 5 minutes
_BURST_MIN = 8            # >= this many blocks inside the window is a burst
_PERSIST_MIN = 5         # same target blocked >= this many times = persistence


def _classify(text: str) -> str:
    for name, rx in _CATEGORIES:
        if rx.search(text or ""):
            return name
    return "other"


@dataclass
class Signals:
    """Deterministic suspicion signals over the window — no model involved."""
    block_categories: dict = field(default_factory=dict)   # category -> count
    alarming_examples: list = field(default_factory=list)  # up to N concrete lines
    by_agent: dict = field(default_factory=dict)           # agent -> {total,blocked}
    persistence: list = field(default_factory=list)        # repeatedly-blocked targets
    bursts: list = field(default_factory=list)             # {at, count} spikes of blocks
    holds: list = field(default_factory=list)              # rug-pull / toolset holds
    high_scan_flags: int = 0
    off_hours_blocks: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def compute_signals(events: list[dict]) -> Signals:
    decisions = [r for r in events if r.get("event") == "decision"]
    blocks = [r for r in decisions if (r.get("effective") or r.get("decision")) in
              ("block", "hold")]

    cats: Counter = Counter()
    examples: list = []
    for r in blocks:
        text = f"{r.get('reason','')} {r.get('resource','')}"
        c = _classify(text)
        cats[c] += 1
        if c in _ALARMING and len(examples) < 12:
            examples.append({
                "category": c,
                "agent": r.get("agent") or r.get("session") or "-",
                "tool": r.get("tool", ""),
                "target": (r.get("resource", "") or "")[:120],
                "reason": re.sub(r"\s*\[[a-z]+:[^\]]*\]\s*$", "",
                                 r.get("reason", "")),
            })

    # per-agent totals and block counts
    agents: dict = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in decisions:
        a = r.get("agent") or r.get("session") or "-"
        agents[a]["total"] += 1
        if (r.get("effective") or r.get("decision")) in ("block", "hold"):
            agents[a]["blocked"] += 1

    # persistence: the same target blocked again and again
    tgt: Counter = Counter()
    for r in blocks:
        t = r.get("resource", "")
        if t:
            tgt[t] += 1
    persistence = [{"target": t[:120], "blocked": n}
                   for t, n in tgt.most_common() if n >= _PERSIST_MIN]

    # rug-pull / toolset holds
    holds = [{"server": r.get("server", ""), "reason": r.get("reason", "")}
             for r in events
             if r.get("event") in ("toolset_held", "toolset_changed")][:10]

    # high-severity scan flags
    high = 0
    for r in decisions:
        for fl in (r.get("flags") or []):
            if isinstance(fl, dict) and str(fl.get("severity", "")).lower() == "high":
                high += 1

    # off-hours blocks (00:00–06:00 local) and burst detection
    times = sorted(t for t in (_parse_ts(r.get("ts", "")) for r in blocks) if t)
    off_hours = sum(1 for t in times if 0 <= t.hour < 6)
    bursts: list = []
    i = 0
    n = len(times)
    while i < n:
        j = i
        while j < n and (times[j] - times[i]).total_seconds() <= _BURST_WINDOW_S:
            j += 1
        count = j - i
        if count >= _BURST_MIN:
            bursts.append({"at": times[i].isoformat(), "count": count})
            i = j
        else:
            i += 1

    return Signals(
        block_categories=dict(cats),
        alarming_examples=examples,
        by_agent={a: v for a, v in agents.items()},
        persistence=persistence,
        bursts=bursts,
        holds=holds,
        high_scan_flags=high,
        off_hours_blocks=off_hours,
    )


def severity(sig: Signals) -> str:
    """clean | notable | suspicious — the headline triage."""
    if (any(sig.block_categories.get(c) for c in _ALARMING)
            or sig.persistence or sig.holds or sig.bursts
            or sig.high_scan_flags):
        return "suspicious"
    if sum(sig.block_categories.values()):
        return "notable"
    return "clean"


def reports_dir() -> Path:
    d = audit.home() / "reports"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _hours(window) -> float:
    if isinstance(window, (int, float)):
        return float(window)
    w = str(window).strip().lower()
    if w in WINDOWS:
        return WINDOWS[w]
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([hdw]?)", w)
    if m:
        v = float(m.group(1))
        return v * {"": 1, "h": 1, "d": 24, "w": 168}[m.group(2)]
    return 24.0


@dataclass
class Analysis:
    window_hours: float
    severity: str
    facts: dict
    signals: dict
    narrative: str = ""


def analyze(window="day", *, cfg=None, use_ai: bool = True) -> Analysis:
    """Review the audit window. Deterministic signals always; an AI verdict when
    a backend is available and use_ai is set."""
    hours = _hours(window)
    days = hours / 24.0
    events = _read_events(days, "")
    facts = build_facts(days=days)
    sig = compute_signals(events)
    sev = severity(sig)

    narrative = ""
    if use_ai:
        try:
            backend = get_backend(cfg)
            if backend.available():
                narrative = backend.investigate(
                    redact_obj(facts.to_dict()), redact_obj(sig.to_dict())).strip()
        except Exception:
            narrative = ""

    return Analysis(window_hours=hours, severity=sev,
                    facts=facts.to_dict(), signals=sig.to_dict(),
                    narrative=narrative)


# --- rendering / saving ------------------------------------------------------

_SEV_MARK = {"clean": "✓ clean", "notable": "• notable", "suspicious": "⚠ SUSPICIOUS"}


def render_markdown(a: Analysis) -> str:
    t = a.facts.get("totals", {})
    win = a.facts.get("window", {})
    L = [f"# Airlock audit review — {_SEV_MARK.get(a.severity, a.severity)}", ""]
    hrs = a.window_hours
    span = f"{hrs:.0f}h" if hrs < 48 else f"{hrs/24:.0f}d"
    L.append(f"Window: last **{span}**"
             + (f"  ({win.get('from','?')} → {win.get('to','?')})"
                if win.get("from") else ""))
    L.append(f"Decisions: **{t.get('decisions',0)}** — "
             f"{t.get('allowed',0)} allowed, {t.get('asked',0)} asked, "
             f"**{t.get('blocked',0)} blocked**.")
    L.append("")

    if a.narrative:
        L += ["## Analyst", "", a.narrative, ""]

    s = a.signals
    cats = s.get("block_categories", {})
    if cats:
        L += ["## Blocked by category", ""]
        for c, n in sorted(cats.items(), key=lambda kv: -kv[1]):
            mark = " ⚠" if c in _ALARMING else ""
            L.append(f"- **{c}**: {n}{mark}")
        L.append("")

    ex = s.get("alarming_examples") or []
    if ex:
        L += ["## Notable blocked calls", ""]
        for e in ex:
            L.append(f"- `{e['agent']}` **{e['tool']}** `{e['target']}` — "
                     f"{e['reason']} _({e['category']})_")
        L.append("")

    ba = s.get("by_agent", {})
    if len(ba) > 1:
        L += ["## By agent", ""]
        for a_name, v in sorted(ba.items(), key=lambda kv: -kv[1]["blocked"]):
            L.append(f"- **{a_name}**: {v['blocked']} blocked / {v['total']} total")
        L.append("")

    if s.get("persistence"):
        L += ["## Repeated targets (possible persistence)", ""]
        for p in s["persistence"]:
            L.append(f"- `{p['target']}` — blocked {p['blocked']}×")
        L.append("")
    if s.get("bursts"):
        L += ["## Block bursts", ""]
        for b in s["bursts"]:
            L.append(f"- {b['count']} blocks around {b['at']}")
        L.append("")
    if s.get("holds"):
        L += ["## Toolset holds (rug-pull watch)", ""]
        for h in s["holds"]:
            L.append(f"- **{h['server']}** — {h['reason']}")
        L.append("")
    extra = []
    if s.get("high_scan_flags"):
        extra.append(f"{s['high_scan_flags']} high-severity scan flag(s)")
    if s.get("off_hours_blocks"):
        extra.append(f"{s['off_hours_blocks']} block(s) between 00:00–06:00")
    if extra:
        L += ["## Other", "", *[f"- {x}" for x in extra], ""]

    if (not cats and not a.narrative and not s.get("holds")
            and not s.get("high_scan_flags") and not s.get("off_hours_blocks")):
        L.append("_Nothing notable in this window._")
    return "\n".join(L).rstrip() + "\n"


def save(a: Analysis, text: str | None = None) -> Path:
    text = text if text is not None else render_markdown(a)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    p = reports_dir() / f"review-{ts}-{a.severity}.md"
    p.write_text(text, encoding="utf-8")
    try:
        import os
        os.chmod(p, 0o600)
    except Exception:
        pass
    # a durable audit line so the review itself is on the record
    audit.record("audit_review", source="cli", effective=a.severity,
                 reason=f"window={a.window_hours:.0f}h blocked="
                        f"{a.facts.get('totals',{}).get('blocked',0)}",
                 extra=str(p))
    return p
