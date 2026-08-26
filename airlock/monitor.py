"""`airlock monitor` — the live decision screen.

`airlock log` is the rear-view mirror. This is the windscreen: a full-screen
board that updates as decisions land, so you can watch your agents get gated in
real time instead of reading about it afterward. It answers the question a
first-time user actually has — "is this thing doing anything?" — by showing them,
live, that it is.

Dependency-free on purpose: it tails the audit, keeps running counters, and
redraws with plain ANSI. No curses, no extra package, works over SSH.

Rotation handling follows the LOG rather than one file. Rotation renames the live
file into a dated segment and starts a new one, so a tail that only watches
audit.jsonl loses whatever was appended between two refreshes the moment a
rotation happens — and if two rotations land inside one interval, the middle
segment never sat under the live name long enough to be seen at all. So: every
frozen segment (audit-*.jsonl) is read in full exactly once, and the live file
by inode-tracked offset. The overlap that produces — the renamed live file
contains records the live tail already counted, and a file truncated in place
gets re-read from zero — is removed by deduplicating on the record digest,
which the chain makes unique per record. The counters are exact at any
rotation rate.
"""
from __future__ import annotations
import json
import os
import sys
import time
from collections import Counter, deque
from pathlib import Path

from . import audit

_C = {"allow": "\033[32m", "ask": "\033[33m", "block": "\033[31m",
      "hold": "\033[31m", "flag": "\033[36m", "b": "\033[1m", "d": "\033[2m",
      "0": "\033[0m"}
_CLEAR = "\033[2J\033[H"
_SEEN_CAP = 20000      # a double-read is always of a just-seen record, so a
#                      # bounded window deduplicates it without keeping history


def _tone(eff: str) -> str:
    return _C.get(eff, _C["d"])


class _Tail:
    """Incremental reader of the audit across rotations.

    State: which rotated segments have been consumed in full, how far the live
    file has been read (keyed by inode, because rotation replaces it), and a
    bounded window of record digests already counted.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.home = self.path.parent
        self.done_segments: set = set()      # segment names read to the end
        self.live_inode = None
        self.live_offset = 0
        self._seen: set = set()
        self._seen_order: deque = deque()

    def _consider(self, rec: dict, counts: Counter, recent: deque) -> None:
        h = rec.get("h")
        if h:
            # A renamed live file still holds records the live tail counted;
            # the digest is unique per record, so the overlap is dropped here
            # instead of being counted twice.
            if h in self._seen:
                return
            self._seen.add(h)
            self._seen_order.append(h)
            if len(self._seen_order) > _SEEN_CAP:
                self._seen.discard(self._seen_order.popleft())
        eff = rec.get("effective") or rec.get("decision") or "?"
        counts[eff] += 1
        recent.append(rec)

    def _read(self, f, counts: Counter, recent: deque) -> None:
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
            self._consider(rec, counts, recent)

    def _read_file(self, p: Path, offset: int, counts: Counter, recent: deque
                   ) -> int:
        """Read p from offset to its current end. Returns the new offset."""
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                self._read(f, counts, recent)
                return f.tell()
        except OSError:
            return offset

    def ingest(self, counts: Counter, recent: deque) -> None:
        """Consume everything new. Safe to call repeatedly."""
        # 1. Frozen rotated segments not yet consumed, oldest first. A rotation
        #    between two ingests turns the old live file into one of these, so
        #    its final records land here even if they never sat still in the
        #    live file long enough to be seen. Segments are written under the
        #    append lock and the writer re-opens the live path per record, so
        #    once named audit-*.jsonl a file no longer grows.
        names = set()
        for seg in sorted(self.home.glob("audit-*.jsonl")):
            names.add(seg.name)
            if seg.name in self.done_segments:
                continue
            self._read_file(seg, 0, counts, recent)
            self.done_segments.add(seg.name)
        # forget segments pruned from disk, so the set cannot grow unbounded
        # on a monitor that runs for weeks
        if len(self.done_segments) > len(names):
            self.done_segments &= names

        # 2. The live file from where it was last read. A new inode means a
        #    rotation replaced it (its predecessor was covered above); a smaller
        #    size under the same inode means it was truncated in place. Either
        #    way the offset restarts, and any double-read that creates is
        #    dropped by the digest window.
        try:
            st = self.path.stat()
        except OSError:
            self.live_inode, self.live_offset = None, 0
            return
        if (self.live_inode is not None and st.st_ino != self.live_inode) \
                or st.st_size < self.live_offset:
            self.live_offset = 0
        self.live_inode = st.st_ino
        self.live_offset = self._read_file(self.path, self.live_offset,
                                           counts, recent)


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
    tail = _Tail(p)
    tail.ingest(counts, recent)
    if once:
        out.write(render(counts, recent, p))
        out.flush()
        return 0
    try:
        while True:
            out.write(_CLEAR + render(counts, recent, p))
            out.flush()
            time.sleep(interval)
            tail.ingest(counts, recent)
    except KeyboardInterrupt:
        out.write("\n  monitor stopped.\n")
        out.flush()
        return 0
