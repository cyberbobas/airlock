"""`airlock monitor` — the live decision screen.

`airlock log` is the rear-view mirror. This is the windscreen: a full-screen
board that updates as decisions land, so you can watch your agents get gated in
real time instead of reading about it afterward. It answers the question a
first-time user actually has — "is this thing doing anything?" — by showing them,
live, that it is.

Dependency-free on purpose: it tails the audit file, keeps running counters, and
redraws with plain ANSI. No curses, no extra package, works over SSH.
"""
from __future__ import annotations
import json
import sys
import time
from collections import Counter, deque

from . import audit

_C = {"allow": "\033[32m", "ask": "\033[33m", "block": "\033[31m",
      "hold": "\033[31m", "flag": "\033[36m", "b": "\033[1m", "d": "\033[2m",
      "0": "\033[0m"}
_CLEAR = "\033[2J\033[H"


def _tone(eff: str) -> str:
    return _C.get(eff, _C["d"])


def _ingest(path, pos: int, counts: Counter, recent: deque) -> int:
    """Read new records since byte `pos`; update counts + recent. Return new pos."""
    if not path.exists():
        return pos
    try:
        size = path.stat().st_size
    except OSError:
        return pos
    if size < pos:            # the file rotated out from under us; start over
        pos = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(pos)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("event") != "decision":
                continue
            eff = rec.get("effective") or rec.get("decision") or "?"
            counts[eff] += 1
            recent.append(rec)
        pos = f.tell()
    return pos


def _trunc(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def render(counts: Counter, recent: deque, path, *, width: int = 80) -> str:
    total = sum(counts.values())
    head = (f"  {_C['b']}AIRLOCK MONITOR{_C['0']}   {total} decisions   "
            f"{time.strftime('%H:%M:%S')}")
    tallies = []
    for eff in ("allow", "ask", "block", "hold"):
        if counts.get(eff):
            tallies.append(f"{_tone(eff)}{eff} {counts[eff]}{_C['0']}")
    bar = "   ".join(tallies) or f"{_C['d']}waiting for the first decision…{_C['0']}"
    lines = [head, "  " + bar, ""]
    for rec in list(recent)[-18:]:
        eff = rec.get("effective") or rec.get("decision") or "?"
        mark = {"allow": "✓", "ask": "?", "block": "✗", "hold": "✗"}.get(eff, "·")
        who = _trunc(rec.get("tool") or rec.get("server") or "-", 30)
        res = _trunc(rec.get("resource") or rec.get("reason") or "", width - 44)
        ts = (rec.get("ts") or "")[11:19]
        lines.append(f"  {_tone(eff)}{mark}{_C['0']} {_C['d']}{ts}{_C['0']} "
                     f"{who:<30} {_C['d']}{res}{_C['0']}")
    lines.append("")
    lines.append(f"  {_C['d']}{path}   ·   Ctrl-C to exit{_C['0']}")
    return "\n".join(lines) + "\n"


def run(*, n: int = 200, interval: float = 0.5, once: bool = False,
        path=None, out=None) -> int:
    """Tail the audit log and redraw a live board until interrupted.

    `once` renders a single frame (no screen-clear) and returns — used by tests
    and by anyone who wants a one-shot snapshot rather than a live view.
    """
    out = out or sys.stdout
    p = path or audit.audit_path()
    counts: Counter = Counter()
    recent: deque = deque(maxlen=n)
    pos = _ingest(p, 0, counts, recent)
    if once:
        out.write(render(counts, recent, p))
        out.flush()
        return 0
    try:
        while True:
            out.write(_CLEAR + render(counts, recent, p))
            out.flush()
            time.sleep(interval)
            pos = _ingest(p, pos, counts, recent)
    except KeyboardInterrupt:
        out.write("\n  monitor stopped.\n")
        out.flush()
        return 0
