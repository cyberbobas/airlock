"""Append-only, tamper-evident audit log (plane 5: identity + attribution).

Every decision from either enforcement point lands here as one JSON line, and a
compact colored summary is echoed to stderr so a human watching sees it live.

TAMPER EVIDENCE
---------------
Each record carries `prev` (the previous record's digest) and `h` (its own).
The file is therefore a hash chain: editing or deleting any past line breaks
every digest after it, and `airlock verify` reports the exact line where the
chain broke. This is what makes plane 5's claim ("a record of who did what")
worth anything — an attacker with write access can append, but cannot rewrite
history unnoticed.

Chaining alone is *evidence*, not attribution: it proves the file was not edited
in place, but anyone who can append can extend it. Enable signing (see sign.py)
when the log has to stand up as proof rather than as a diagnostic.

The file rotates by size, and the chain continues across rotations — the first
record of a new file carries the last digest of the old one, so a whole rotated
file cannot be dropped without leaving a gap that `airlock verify` reports.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from . import config, sign as signing

try:
    import fcntl  # posix file lock so proxy threads + hook processes don't interleave
except ImportError:  # pragma: no cover
    fcntl = None

GENESIS = "0" * 16
_CHAINED = ("ts", "event", "source", "server", "tool", "decision", "effective",
            "reason", "resource", "detail", "session", "args_digest", "flags", "prev")
MAX_MB = float(os.environ.get("AIRLOCK_AUDIT_MAX_MB", "64"))

# fsync costs ~0.5ms. Paying it on every allowed call taxes the hot path for
# records nobody will ever subpoena; skipping it on a block risks losing the one
# line that mattered. So: always | critical (default) | never.
_FSYNC = os.environ.get("AIRLOCK_AUDIT_FSYNC", "critical").lower()
_CRITICAL = {"block", "hold", "ask", "change", "flag"}


def home() -> Path:
    """$AIRLOCK_HOME, created 0700.

    The audit log records the concrete paths, hosts and commands an agent
    reached for. That is exactly the reconnaissance an attacker on the same box
    would like, so it is not world-readable.
    """
    return config.home()


def audit_path() -> Path:
    return home() / "audit.jsonl"


def _digest(obj) -> str:
    try:
        blob = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
    except Exception:
        blob = repr(obj).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def chain_digest(rec: dict) -> str:
    """Digest over the chained fields only, so adding new optional fields later
    does not invalidate old records."""
    payload = {k: rec.get(k) for k in _CHAINED}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _last_hash_in(path: Path) -> str | None:
    """Last record digest in a file, read from the tail rather than the whole."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            f.seek(max(0, size - 8192))
            for line in reversed(f.read().decode("utf-8", "replace").splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    h = json.loads(line).get("h")
                except Exception:
                    continue
                if h:
                    return h
    except Exception:
        pass
    return None


def _tail_hash(f) -> str:
    """The digest the next record must chain onto.

    When the live file is empty this is NOT genesis: it is the last digest of
    the newest rotated segment. Getting this wrong made rotation forge its own
    chain break — `verify` would report tampering on a file nobody had touched,
    which is worse than no integrity check at all, because it teaches people to
    ignore the alarm.
    """
    try:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size > 0:
            f.seek(max(0, size - 8192))
            for line in reversed(f.read().decode("utf-8", "replace").splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    h = json.loads(line).get("h")
                except Exception:
                    continue
                if h:
                    return h
            return GENESIS
    except Exception:
        return GENESIS
    # live file is empty: continue from the newest rotated segment, if any
    for seg in reversed(sorted(home().glob("audit-*.jsonl"))):
        h = _last_hash_in(seg)
        if h:
            return h
    return GENESIS


_COLOR = {"allow": "\033[32m", "ask": "\033[33m", "block": "\033[31m",
          "flag": "\033[35m", "admit": "\033[36m", "change": "\033[35m",
          "hold": "\033[31m"}
_RESET = "\033[0m"


def _quiet() -> bool:
    return os.environ.get("AIRLOCK_QUIET", "").lower() in ("1", "true", "yes")


def _stderr(effective: str, tool: str, reason: str, extra: str = "") -> None:
    if _quiet():
        return
    c = _COLOR.get(effective, "")
    tag = effective.upper().ljust(6)
    line = f"{c}[airlock] {tag}{_RESET} {tool}  {reason}"
    if extra:
        line += f"  {extra}"
    print(line, file=sys.stderr, flush=True)


def _now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1000):03d}Z"


def record(event: str, *, source: str, tool: str = "", server: str = "",
           decision: str = "", effective: str = "", reason: str = "",
           args=None, flags=None, session: str = "", extra: str = "",
           resource: str = "") -> dict:
    rec = {
        "ts": _now(),
        "event": event,           # decision | toolset_admitted | toolset_held | scan_flag
        "source": source,         # mcp | hook | askd | cli
        "server": server,
        "tool": tool,
        "decision": decision,     # allow | ask | block (intended)
        "effective": effective,   # what actually happened
        "reason": reason,
        "resource": resource,     # the concrete target (path / host / command)
        "detail": extra,          # human-readable payload (tool list, scan hit)
        "session": session or os.environ.get("AIRLOCK_SESSION", ""),
        "args_digest": _digest(args) if args is not None else "",
        "flags": flags or [],
    }
    path = audit_path()
    _rotate_if_needed(path)
    with open(path, "a+b") as f:
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            rec["prev"] = _tail_hash(f)
            rec["h"] = chain_digest(rec)
            alg = signing.mode()
            if alg != signing.ALG_NONE:
                sig = signing.sign(rec["h"])
                if sig:
                    rec["alg"], rec["sig"] = alg, sig
            f.seek(0, os.SEEK_END)
            f.write((json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8"))
            f.flush()
            if _FSYNC == "always" or (_FSYNC == "critical"
                                      and (effective or decision) in _CRITICAL):
                os.fsync(f.fileno())
        finally:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    _stderr(effective or decision or event, tool or server, reason, extra)
    return rec


def chain_ledger() -> list[dict]:
    """Every rotation handover ever recorded, oldest first."""
    p = home() / "audit.chain"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def rotated_files() -> list[Path]:
    """Rotated segments, oldest first, then the live file."""
    h = home()
    olds = sorted(h.glob("audit-*.jsonl"))
    live = audit_path()
    return [*olds, *([live] if live.exists() else [])]


def _rotate_if_needed(path: Path) -> None:
    try:
        if MAX_MB <= 0 or not path.exists():
            return
        if path.stat().st_size < MAX_MB * 1024 * 1024:
            return
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        dest = path.with_name(f"audit-{stamp}.jsonl")
        if dest.exists():
            return
        os.rename(path, dest)
        os.chmod(dest, 0o600)
        # Append to the rotation ledger. Without it, deleting a whole segment is
        # invisible: the live file simply looks like the start of history. The
        # ledger is what turns "the chain is intact" into "the chain is intact
        # AND nothing was quietly removed from it".
        last = _last_hash_in(dest)
        if last:
            with open(home() / "audit.chain", "a", encoding="utf-8") as led:
                led.write(json.dumps({"segment": dest.name, "last": last,
                                      "at": _now()}) + "\n")
    except Exception:
        pass          # never let housekeeping break a decision


def verify(path: Path | None = None, *, all_segments: bool = False
           ) -> tuple[bool, int, str]:
    """Walk the hash chain. Return (ok, n_records, message).

    With all_segments, follow the chain across rotated files too, so dropping a
    whole segment is detected rather than silently forgiven.
    """
    if all_segments and path is None:
        files = rotated_files()
    else:
        files = [Path(path) if path else audit_path()]
    files = [f for f in files if f.exists()]
    if not files:
        return True, 0, "no audit log yet"

    # A segment named in the rotation ledger that is gone, or whose tail no
    # longer matches what was recorded, means history was removed wholesale.
    if all_segments:
        h = home()
        for entry in chain_ledger():
            seg = h / str(entry.get("segment", ""))
            if not seg.exists():
                return False, 0, (f"audit segment {entry.get('segment')} is missing "
                                  f"— {entry.get('at','?')} rotation was deleted")
            got = _last_hash_in(seg)
            if got != entry.get("last"):
                return False, 0, (f"audit segment {entry.get('segment')} was "
                                  f"truncated — its last digest should be "
                                  f"{entry.get('last')}, found {got}")

    prev = GENESIS
    n = 0
    unsigned = 0
    badsig = 0
    for p in files:
        first = True
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                return False, n, f"{p.name} line {lineno}: not valid JSON"
            n += 1
            if "h" not in rec:            # pre-chain record, tolerate but reset
                prev = GENESIS
                first = False
                continue
            if rec.get("prev") != prev:
                if first and not all_segments:
                    prev = rec.get("prev")   # verifying one segment in isolation
                elif first and prev == GENESIS:
                    prev = rec.get("prev")   # first segment of the whole history
                else:
                    where = ("across the rotation boundary into" if first
                             else "at")
                    return False, n, (
                        f"chain break {where} {p.name} line {lineno}: expected "
                        f"prev={prev}, got {rec.get('prev')} "
                        f"(a record or a whole segment was deleted or reordered)")
            if chain_digest(rec) != rec["h"]:
                return False, n, (f"{p.name} line {lineno}: digest mismatch — "
                                  f"this record was edited")
            if rec.get("sig"):
                if not signing.verify_one(rec["h"], rec["sig"], rec.get("alg", "")):
                    badsig += 1
            else:
                unsigned += 1
            prev = rec["h"]
            first = False

    msg = f"chain intact across {n} records"
    if len(files) > 1:
        msg += f" in {len(files)} segments"
    if badsig:
        return False, n, f"{msg}, but {badsig} signature(s) do not verify"
    if unsigned and unsigned < n:
        msg += f" ({n - unsigned} signed, {unsigned} unsigned)"
    elif unsigned == n and signing.mode() != signing.ALG_NONE:
        msg += " (unsigned — signing was enabled after these were written)"
    elif not unsigned and n:
        msg += " (all signed)"
    return True, n, msg
