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
        # session-wide aggregates for the dashboard (whole history, not just the
        # bounded recent feed)
        self.blocked: Counter = Counter()    # block reason -> count
        self.tools: Counter = Counter()      # tool/server -> count
        self.times: deque = deque(maxlen=4000)   # arrival times, for the rate
        self.agents: Counter = Counter()         # agent -> total decisions
        self.agent_blocked: Counter = Counter()  # agent -> blocked count

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
        self.tools[rec.get("tool") or rec.get("server") or "-"] += 1
        self.times.append(time.time())
        agent = _agent_of(rec)
        self.agents[agent] += 1
        if eff in ("block", "hold"):
            reason, _ = _clean_reason(rec.get("reason"))
            self.blocked[reason or "blocked"] += 1
            self.agent_blocked[agent] += 1

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
    if n <= 1:
        return s[:max(n, 0)]
    return s if len(s) <= n else s[: n - 1] + "…"


_TAG_RE = None


def _clean_reason(reason: str):
    """Drop the trailing `[ask:...]`/`[guard:...]` provenance tag for display,
    and report whether a human resolved it (an `ask:` human channel)."""
    global _TAG_RE
    if _TAG_RE is None:
        import re
        _TAG_RE = re.compile(r"\s*\[([a-z]+):([a-z-]+)\]\s*$")
    reason = reason or ""
    human = False
    m = _TAG_RE.search(reason)
    if m:
        if m.group(1) == "ask" and m.group(2) in ("socket", "osascript",
                                                  "zenity", "tty", "remembered"):
            human = True
        reason = reason[: m.start()].rstrip()
    return reason, human


def _agent_of(rec: dict) -> str:
    """Which agent a decision belongs to. `agent` (from $AIRLOCK_AGENT) is the
    intended label; fall back to the session id, then the plane, so a gate that
    was never told the agent name still groups calls sensibly."""
    a = rec.get("agent") or rec.get("session") or rec.get("source") or "-"
    return a or "-"


def _bar(frac: float, cells: int) -> str:
    frac = 0.0 if frac < 0 else (1.0 if frac > 1 else frac)
    filled = int(round(frac * cells))
    return "█" * filled + "░" * (cells - filled)


def _rate(times: deque, window: float = 3.0) -> float:
    """Decisions/second over the last `window`, measured from real arrival
    spread. Returns 0 when a whole journal was just bulk-loaded (all arrivals
    in one instant) so a static replay does not report an absurd rate."""
    if len(times) < 2:
        return 0.0
    now = time.time()
    recent = [t for t in times if t >= now - window]
    if len(recent) < 2:
        return 0.0
    span = recent[-1] - recent[0]
    if span < 0.2:                      # bulk-loaded, not a live stream
        return 0.0
    return (len(recent) - 1) / span


def render(counts: Counter, recent: deque, tail, path, *, width: int = None,
           feed: int = None, height: int = None) -> str:
    if width is None or height is None:
        import shutil
        ts = shutil.get_terminal_size((100, 24))
        width = width if width is not None else ts.columns
        height = height if height is not None else ts.lines
    W = max(width, 60)
    C = _C
    total = sum(counts.values())
    allow = counts.get("allow", 0)
    ask = counts.get("ask", 0)
    block = counts.get("block", 0) + counts.get("hold", 0)
    rate = _rate(getattr(tail, "times", deque()))
    agents = getattr(tail, "agents", Counter())
    ag_blocked = getattr(tail, "agent_blocked", Counter())
    multi = len(agents) > 1                # more than one agent behind the gate

    L = []
    # ---- header -----------------------------------------------------------
    ag_hint = f"   {C['d']}{len(agents)} agents{C['0']}" if multi else ""
    L.append(f"  {C['b']}AIRLOCK MONITOR{C['0']}   {C['b']}{total}{C['0']} "
             f"decisions   {C['d']}{rate:.0f}/s   {time.strftime('%H:%M:%S')}"
             f"{C['0']}{ag_hint}")
    L.append("")
    # ---- distribution bars ------------------------------------------------
    cells = max(min(W - 40, 44), 10)
    for label, cnt in (("allow", allow), ("block", block), ("ask", ask)):
        frac = (cnt / total) if total else 0.0
        L.append(f"  {_tone(label)}{label:<6}{C['0']} {_tone(label)}"
                 f"{_bar(frac, cells)}{C['0']}  {C['b']}{cnt}{C['0']} "
                 f"{C['d']}({100 * frac:.0f}%){C['0']}")
    L.append("")
    # ---- who is being blocked (only when >1 agent is behind the gate) ------
    if multi:
        chips = []
        for ag in sorted(agents, key=lambda a: (-agents[a], a))[:6]:
            tot = agents[ag]
            nb = ag_blocked.get(ag, 0)
            col = _C["block"] if nb else _C["allow"]
            chips.append(f"{C['b']}{ag}{C['0']} {col}✗{nb}{C['0']}"
                         f"{C['d']}/{tot}{C['0']}")
        L.append(f"  {C['b']}BY AGENT{C['0']}  " + "   ".join(chips))
        L.append("")
    # ---- two panels: TOP BLOCKED | BUSIEST TOOLS --------------------------
    colw = max((W - 6) // 2, 20)
    blocked = getattr(tail, "blocked", Counter()).most_common(6)
    busiest = getattr(tail, "tools", Counter()).most_common(6)
    L.append(f"  {C['b']}{'TOP BLOCKED':<{colw}}{C['0']}{C['b']}BUSIEST{C['0']}")
    for i in range(6):
        left = right = ""
        if i < len(blocked):
            rsn, n = blocked[i]
            left = f"{_C['block']}{n:>5}{C['0']} {_trunc(rsn, colw - 8)}"
            left_pad = colw - (len(f"{n:>5}") + 1 + len(_trunc(rsn, colw - 8)))
            left = left + " " * max(left_pad, 0)
        else:
            left = " " * colw
        if i < len(busiest):
            tl, n = busiest[i]
            right = f"{C['flag']}{n:>5}{C['0']} {C['d']}{_trunc(tl, colw - 8)}{C['0']}"
        L.append("  " + left + right)
    L.append("")
    # ---- live feed: two lines per entry, the reason on its own full-width
    #      line so it is never chopped, a faint rule between entries -----------
    if feed is None:
        overhead = 11 + (2 if multi else 0)
        feed = max(((height or 24) - overhead) // 3, 4)   # 3 rows per entry
    rows = list(recent)[-feed:]
    aw = 8 if multi else 0                     # agent column, only if >1 agent
    tw = 20                                    # tool column (fixed → no jitter)
    rule = "  " + C['d'] + "─" * max(W - 4, 10) + C['0']

    L.append(f"  {C['b']}LIVE{C['0']}  {C['d']}newest last   "
             f"{C['0']}{C['allow']}✓ allowed{C['0']}   "
             f"{C['block']}✗ blocked{C['0']}   {C['ask']}? asked{C['0']} "
             f"{C['d']}(airlock flagged it; the agent decides){C['0']}")
    L.append(rule)
    for rec in rows:
        eff = rec.get("effective") or rec.get("decision") or "?"
        mark = {"allow": "✓", "ask": "?", "block": "✗", "hold": "⏸"}.get(eff, "·")
        blocked = eff in ("block", "hold")
        emph = C["b"] if blocked else ""
        who = _trunc(rec.get("tool") or rec.get("server") or "-", tw)
        reason, _human = _clean_reason(rec.get("reason"))
        ts = (rec.get("ts") or "")[11:19]
        agent_col = ""
        if aw:
            agent_col = f"{C['flag']}{_trunc(_agent_of(rec), aw):<{aw}}{C['0']}  "
        # line 1: mark  [agent]  tool   command (command flexes, only it truncs)
        cmd_w = max(W - (2 + 1 + 2 + (aw + 2 if aw else 0) + tw + 3), 12)
        cmd = _trunc(rec.get("resource") or reason or "", cmd_w)
        L.append(f"  {emph}{_tone(eff)}{mark}{C['0']}  {agent_col}"
                 f"{emph}{_tone(eff)}{who:<{tw}}{C['0']}   {cmd}")
        # line 2: WHY. For a block this is the whole point, so it is in the block
        # colour and labelled; an allow/ask reason stays quiet and dim.
        if blocked:
            why = _trunc("blocked: " + reason, max(W - 15, 20))
            why_col = C["block"]
        else:
            why = _trunc(reason, max(W - 15, 20))
            why_col = C["d"]
        pad = max(W - 6 - len(why) - 8, 1)
        L.append(f"      {why_col}{why}{C['0']}{' ' * pad}{C['d']}{ts}{C['0']}")
        L.append(rule)
    L.append(f"  {C['d']}{path}   ·   Ctrl-C to exit{C['0']}")
    return "\n".join(L) + "\n"


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
        # A one-shot snapshot is not bound by screen height — show the whole
        # recent window rather than just what would fit a live frame.
        out.write(render(counts, recent, tail, p, feed=max(len(recent), 12)))
        out.flush()
        return 0
    # Draw on the ALTERNATE screen buffer, like htop/less/vim: a separate screen
    # that never touches the scrollback. The old approach cleared with ESC[2J,
    # which on VTE terminals (GNOME Terminal) pushes each cleared frame into the
    # scrollback — so every redraw left a stacked copy you had to scroll through.
    # `?1049h` enters the alt screen; each frame homes the cursor and clears to
    # the end of the screen (so a shorter frame leaves no leftovers); `?1049l`
    # on exit restores the terminal exactly as it was.
    _ENTER, _LEAVE = "\033[?1049h\033[?25l", "\033[?25h\033[?1049l"
    _HOME, _CLR_DOWN = "\033[H", "\033[0J"
    # Put the terminal in cbreak + no-echo for the duration, like any fullscreen
    # TUI. Without it, a mouse wheel (which the terminal turns into arrow-key
    # bytes on the alternate screen) and any keystroke get echoed into the frame
    # as stray characters. cbreak keeps signals on, so Ctrl-C still stops us.
    fd = old = None
    try:
        import termios
        import tty
        if hasattr(sys.stdin, "fileno") and sys.stdin.isatty():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
    except Exception:
        fd = old = None
    out.write(_ENTER)
    out.flush()
    try:
        while True:
            # Clear each line to its end (ESC[K) as we redraw, then clear the
            # rest of the screen (ESC[0J). Without the per-line clear, a new
            # frame's shorter line leaves the tail of the previous longer line
            # behind — the ghosting that made commands read as "cat .envME.md".
            frame = render(counts, recent, tail, p).replace("\n", "\033[K\n")
            out.write(_HOME + frame + _CLR_DOWN)
            out.flush()
            time.sleep(interval)
            tail.ingest(counts, recent)
    except KeyboardInterrupt:
        pass
    finally:
        out.write(_LEAVE)
        out.flush()
        if fd is not None and old is not None:
            try:
                import termios
                termios.tcflush(fd, termios.TCIFLUSH)   # drop buffered wheel/keys
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass
    out.write("  monitor stopped.\n")
    out.flush()
    return 0
