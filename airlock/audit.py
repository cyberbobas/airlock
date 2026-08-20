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

THE ROTATION LEDGER
-------------------
`audit.chain` records one line per handover. It is itself a hash chain (each
entry carries `prev` + `h`, signed alongside the records when signing is on),
and every handover is *anchored*: the first record written into the new live
file names the ledger entry's digest, inside a chained field. So the two
structures hold each other up — removing a ledger line contradicts the audit
log, and editing the audit log to match breaks the record chain.

That closes the obvious next move against a bare ledger: dropping a segment and
the one ledger line that named it. It does not make the log tamper-*proof* — a
same-privilege attacker holding the HMAC key can re-forge both. Off-box shipping
or `AIRLOCK_SIGN=ed25519` with an external key is what raises that ceiling.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
import sys
import threading
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
# The ledger chains over its own fields. `detail` on the anchor record carries
# "ledger=<digest>" rather than a dedicated key, because adding a name to
# _CHAINED would change every historical record's digest and invalidate logs
# written by an older version.
_LEDGER_CHAINED = ("segment", "last", "at", "prev")
_ANCHOR = "ledger="
_ROTATING = False
# Written into the first record of every live file this version creates, so a
# missing audit.head can be told apart from a log that never had one. Without
# it, truncating the tail and deleting the checkpoint produced the same verdict
# as an install that predates checkpointing — the attacker got to choose which
# story the auditor read, for the price of one `rm`.
_HEAD_MARK = "checkpointed"

# Rotation renames the live file. Anything appending through an fd it opened
# before the rename keeps writing into the *rotated* segment — after the ledger
# already recorded that segment's final digest. The result was a log that
# reported itself truncated under nothing worse than two busy agents. So
# rotation and appending serialise on a lock file, which is the one thing in
# here that never gets renamed out from under a waiter.
_MUTEX = threading.RLock()
_flock_depth = 0
_flock_fh = None


def lock_path() -> Path:
    return home() / "audit.lock"


@contextlib.contextmanager
def _append_lock():
    """Exclusive across processes, reentrant within one.

    Reentrant because `_anchor` writes an ordinary audit record from inside
    rotation, which is itself inside this lock; a plain flock would deadlock
    against itself there.
    """
    global _flock_depth, _flock_fh
    with _MUTEX:
        if _flock_depth == 0:
            try:
                _flock_fh = open(lock_path(), "a+")
                try:
                    os.chmod(lock_path(), 0o600)
                except OSError:
                    pass
                if fcntl:
                    fcntl.flock(_flock_fh.fileno(), fcntl.LOCK_EX)
            except OSError:
                _flock_fh = None      # unwritable home: still record, unlocked
        _flock_depth += 1
        try:
            yield
        finally:
            _flock_depth -= 1
            if _flock_depth == 0 and _flock_fh is not None:
                try:
                    if fcntl:
                        fcntl.flock(_flock_fh.fileno(), fcntl.LOCK_UN)
                    _flock_fh.close()
                finally:
                    _flock_fh = None
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


_CTRL = {c: f"\\x{c:02x}" for c in range(0x20)}
_CTRL[0x7f] = "\\x7f"


def safe(text, limit: int = 0) -> str:
    """Render an attacker-controlled string on one line, escapes disarmed.

    Every `resource` and `reason` in this log came from the arguments of a call
    somebody was trying to make. A newline inside one lets a crafted file path
    print a second, entirely fabricated decision line in `airlock log`; an ANSI
    escape lets it erase the real ones. Evidence you can typeset is not
    evidence.
    """
    out = str(text if text is not None else "").translate(_CTRL)
    return out[:limit] if limit else out


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
    line = f"{c}[airlock] {tag}{_RESET} {safe(tool)}  {safe(reason)}"
    if extra:
        line += f"  {safe(extra)}"
    print(line, file=sys.stderr, flush=True)


def _now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1000):03d}Z"


def record(event: str, *, source: str, tool: str = "", server: str = "",
           decision: str = "", effective: str = "", reason: str = "",
           args=None, flags=None, session: str = "", extra: str = "",
           resource: str = "") -> dict:
    if not _ROTATING and event != "audit_start":
        try:
            live = audit_path()
            if not live.exists() or live.stat().st_size == 0:
                _mark_checkpointed()
        except OSError:
            pass
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
    with _append_lock():
        _write_record(path, rec, effective, decision)
    _stderr(effective or decision or event, tool or server, reason, extra)
    return rec


def _write_record(path: Path, rec: dict, effective: str, decision: str) -> None:
    """Append one chained record. Caller holds the append lock."""
    _rotate_if_needed(path)
    existed = path.exists() and path.stat().st_size > 0
    with open(path, "a+b") as f:
        if not existed:
            # Rotated segments were chmod 0600 while the live file — the one
            # holding the freshest paths, hosts and commands — kept whatever
            # the umask gave it, usually 0644.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
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
        except OSError:
            return        # an unwritable log must not stop the enforcement
    # Continue from our own last checkpoint when this process wrote it and the
    # chain has not moved underneath us; otherwise another writer was here and
    # the file is the only truth.
    prior = _head_cache
    if not (prior and prior.get("last") == rec.get("prev")):
        prior = read_head() or {}
    _write_head(int(prior.get("count", 0)) + 1, rec["h"])


def head_path() -> Path:
    return home() / "audit.head"


def read_head() -> dict | None:
    """The last checkpoint: how many records exist and what the final digest is."""
    p = head_path()
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8").strip() or "{}")
        return d if isinstance(d, dict) and "last" in d else None
    except Exception:
        return None


_head_cache: dict | None = None
_head_fd: tuple[str, int] | None = None      # (path, fd), reused under the lock


def _write_head(count: int, last: str) -> None:
    """Checkpoint the tail after every record.

    The chain proves no record was EDITED. It says nothing about records that
    were DELETED FROM THE END — and the end is exactly where someone covering
    their tracks would cut, because that is where their own decisions are. The
    ledger only ever covered rotated segments, so truncating the live file was
    invisible: `verify` reported an intact chain over a log with the last five
    minutes removed.

    One small atomic write per record, no fsync: cheap next to the append it
    accompanies, and it turns tail truncation into a mismatch someone can see.
    """
    h = {"count": count, "last": last, "at": _now()}
    alg = signing.mode()
    if alg != signing.ALG_NONE:
        sig = signing.sign(f"{count}:{last}")
        if sig:
            h["alg"], h["sig"] = alg, sig
    global _head_cache
    try:
        p = head_path()
        blob = (json.dumps(h, ensure_ascii=False) + "\n").encode("utf-8")
        # Written in place rather than through a temp file and rename. A torn
        # write reads back as unparseable, which `read_head` reports as *no*
        # checkpoint — "the tail cannot be proven", the safe direction — so the
        # rename buys nothing and costs three syscalls on every single decision.
        # Reuse the descriptor across records. We only ever get here holding
        # the append lock, so there is no interleaving to worry about, and the
        # open/close pair was the whole remaining cost of checkpointing.
        global _head_fd
        key = str(p)
        if _head_fd is None or _head_fd[0] != key:
            if _head_fd is not None:
                try:
                    os.close(_head_fd[1])
                except OSError:
                    pass
            _head_fd = (key, os.open(p, os.O_WRONLY | os.O_CREAT, 0o600))
        fd = _head_fd[1]
        os.ftruncate(fd, 0)
        os.pwrite(fd, blob, 0)
        _head_cache = h
    except OSError:
        _head_cache = None    # a checkpoint we cannot write must not stop a decision
        if _head_fd is not None:
            try:
                os.close(_head_fd[1])
            except OSError:
                pass
            _head_fd = None


def head_ok(head: dict) -> bool:
    """Was this checkpoint written by someone holding the signing key?"""
    if not head.get("sig"):
        return signing.mode() == signing.ALG_NONE
    return signing.verify_one(f"{head.get('count')}:{head.get('last')}",
                              head["sig"], head.get("alg", ""))


def ledger_path() -> Path:
    return home() / "audit.chain"


def ledger_digest(entry: dict) -> str:
    payload = {k: entry.get(k) for k in _LEDGER_CHAINED}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def note_gate(fingerprint: str, description: str) -> bool:
    """Record a change in the gate's own configuration, once per change.

    Every enforcement point calls this at startup. In steady state it costs one
    small read and writes nothing; the moment the policy file, its contents,
    the mode or a weakening environment variable differs from what was last
    seen, the log gets one line saying so. Without it a swapped policy produced
    decisions indistinguishable from ordinary ones.
    """
    p = home() / "gate.state"
    try:
        was = p.read_text(encoding="utf-8").strip()
    except OSError:
        was = ""
    if was == fingerprint:
        return False
    try:
        record("gate_config", source="audit", effective="flag",
               reason=("the gate's configuration changed" if was
                       else "gate configuration recorded"),
               extra=description[:400])
    except Exception:
        return False
    try:
        tmp = p.with_suffix(".state.tmp")
        tmp.write_text(fingerprint, encoding="utf-8")
        os.replace(tmp, p)
        os.chmod(p, 0o600)
    except OSError:
        pass
    return True


def chain_ledger(*, strict: bool = False) -> list[dict]:
    """Every rotation handover ever recorded, oldest first.

    strict keeps unparseable lines as ``{"_bad": lineno}`` so `verify` can call
    a corrupted ledger corrupted instead of silently reading past it.
    """
    p = ledger_path()
    if not p.exists():
        return []
    out = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            if strict:
                out.append({"_bad": lineno})
    return out


def _ledger_append(segment: str, last: str) -> str | None:
    """Record one handover, chained onto the previous one. Returns its digest."""
    p = ledger_path()
    try:
        with open(p, "a+", encoding="utf-8") as f:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                prior = chain_ledger()
                prev = (prior[-1].get("h") or GENESIS) if prior else GENESIS
                e = {"segment": segment, "last": last, "at": _now(), "prev": prev}
                e["h"] = ledger_digest(e)
                alg = signing.mode()
                if alg != signing.ALG_NONE:
                    sig = signing.sign(e["h"])
                    if sig:
                        e["alg"], e["sig"] = alg, sig
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                if fcntl:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        os.chmod(p, 0o600)
        return e["h"]
    except Exception:
        return None


def verify_ledger() -> tuple[bool, str, set[str]]:
    """Walk the rotation ledger. Return (ok, message, digests seen).

    Checks three separate things, because they fail differently: the ledger's
    own chain (a line was edited or removed from the middle), each named
    segment still being present and ending where it said (a segment was deleted
    or truncated), and the signatures when signing is on.
    """
    entries = chain_ledger(strict=True)
    seen: set[str] = set()
    h = home()
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        if "_bad" in e:
            return False, f"rotation ledger line {e['_bad']}: not valid JSON", seen
        if "h" not in e:                    # written before the ledger was chained
            prev = GENESIS
            continue
        if e.get("prev") != prev:
            if i == 1 and prev == GENESIS:
                prev = e.get("prev")        # ledger predates chaining, or was pruned
            else:
                return False, (f"rotation ledger entry {i} ({e.get('segment')}): "
                               f"expected prev={prev}, got {e.get('prev')} — a "
                               f"handover record was removed or reordered"), seen
        if ledger_digest(e) != e["h"]:
            return False, (f"rotation ledger entry {i} ({e.get('segment')}) was "
                           f"edited"), seen
        if e.get("sig") and not signing.verify_one(e["h"], e["sig"],
                                                   e.get("alg", "")):
            return False, (f"rotation ledger entry {i} ({e.get('segment')}): "
                           f"signature does not verify"), seen
        prev = e["h"]
        seen.add(e["h"])

    for e in entries:
        if "_bad" in e:
            continue
        seg = h / str(e.get("segment", ""))
        if not seg.exists():
            return False, (f"audit segment {e.get('segment')} is missing — "
                           f"{e.get('at','?')} rotation was deleted"), seen
        got = _last_hash_in(seg)
        if got != e.get("last"):
            return False, (f"audit segment {e.get('segment')} was truncated — its "
                           f"last digest should be {e.get('last')}, found {got}"), seen
    return True, "", seen


def rotated_files() -> list[Path]:
    """Rotated segments, oldest first, then the live file."""
    h = home()
    olds = sorted(h.glob("audit-*.jsonl"))
    live = audit_path()
    return [*olds, *([live] if live.exists() else [])]


def _rotate_if_needed(path: Path) -> None:
    try:
        if _ROTATING or MAX_MB <= 0 or not path.exists():
            return
        if path.stat().st_size < MAX_MB * 1024 * 1024:
            return
        # Microseconds, not seconds. With a second-resolution name every
        # rotation after the first one inside the same second hit an existing
        # file and returned — so a busy second silently stopped rotating and
        # the log grew past its cap. The suffix has to keep sorting in
        # chronological order too, because segments are walked by name.
        t = time.time()
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(t)) + f"{int(t % 1 * 1e6):06d}"
        dest = path.with_name(f"audit-{stamp}.jsonl")
        while dest.exists():
            stamp = f"{int(stamp) + 1:020d}"
            dest = path.with_name(f"audit-{stamp}.jsonl")
        os.rename(path, dest)
        os.chmod(dest, 0o600)
        # Append to the rotation ledger. Without it, deleting a whole segment is
        # invisible: the live file simply looks like the start of history. The
        # ledger is what turns "the chain is intact" into "the chain is intact
        # AND nothing was quietly removed from it".
        last = _last_hash_in(dest)
        if last:
            digest = _ledger_append(dest.name, last)
            if digest:
                _anchor(dest.name, digest)
    except Exception:
        pass          # never let housekeeping break a decision


def _anchor(segment: str, ledger_h: str) -> None:
    """Open the new live file with a record naming the ledger entry.

    A ledger nobody references can be shortened: drop the segment, drop its one
    line, and the remaining ledger is self-consistent. The anchor makes that
    trade impossible — the digest lives in a chained field of a normal audit
    record, so removing it breaks the record chain instead.
    """
    global _ROTATING
    if _ROTATING:
        return
    _ROTATING = True
    try:
        record("rotation", source="audit", effective="admit",
               reason="audit log rotated", resource=segment,
               extra=f"{_ANCHOR}{ledger_h}")
    except Exception:
        pass
    finally:
        _ROTATING = False

# Rotation renames the live file. Anything appending through an fd it opened
# before the rename keeps writing into the *rotated* segment — after the ledger
# already recorded that segment's final digest. The result was a log that
# reported itself truncated under nothing worse than two busy agents. So
# rotation and appending serialise on a lock file, which is the one thing in
# here that never gets renamed out from under a waiter.
_MUTEX = threading.RLock()
_flock_depth = 0
_flock_fh = None


def lock_path() -> Path:
    return home() / "audit.lock"


@contextlib.contextmanager
def _append_lock():
    """Exclusive across processes, reentrant within one.

    Reentrant because `_anchor` writes an ordinary audit record from inside
    rotation, which is itself inside this lock; a plain flock would deadlock
    against itself there.
    """
    global _flock_depth, _flock_fh
    with _MUTEX:
        if _flock_depth == 0:
            try:
                _flock_fh = open(lock_path(), "a+")
                try:
                    os.chmod(lock_path(), 0o600)
                except OSError:
                    pass
                if fcntl:
                    fcntl.flock(_flock_fh.fileno(), fcntl.LOCK_EX)
            except OSError:
                _flock_fh = None      # unwritable home: still record, unlocked
        _flock_depth += 1
        try:
            yield
        finally:
            _flock_depth -= 1
            if _flock_depth == 0 and _flock_fh is not None:
                try:
                    if fcntl:
                        fcntl.flock(_flock_fh.fileno(), fcntl.LOCK_UN)
                    _flock_fh.close()
                finally:
                    _flock_fh = None


def _mark_checkpointed() -> None:
    """Record, inside the chain, that this log is checkpointed."""
    global _ROTATING
    if _ROTATING:
        return
    _ROTATING = True
    try:
        record("audit_start", source="audit", effective="admit",
               reason="audit log opened", extra=_HEAD_MARK)
    except Exception:
        pass
    finally:
        _ROTATING = False


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
    ledger_seen: set[str] = set()
    if all_segments:
        ok, msg, ledger_seen = verify_ledger()
        if not ok:
            return False, 0, msg

    prev = GENESIS
    n = 0
    unsigned = 0
    badsig = 0
    anchors: list[tuple[str, str]] = []      # (segment named, ledger digest)
    expects_head = False
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
            if rec.get("event") == "audit_start" and rec.get("detail") == _HEAD_MARK:
                expects_head = True
            if rec.get("event") == "rotation" and str(rec.get("detail", "")).startswith(_ANCHOR):
                anchors.append((str(rec.get("resource", "")),
                                str(rec["detail"])[len(_ANCHOR):]))
            prev = rec["h"]
            first = False

    # Every handover the log itself vouches for must still be in the ledger.
    # This is the half that catches "delete the segment AND its ledger line".
    if all_segments:
        for segment, digest in anchors:
            if digest not in ledger_seen:
                return False, n, (
                    f"the audit log records a rotation to {segment} that the "
                    f"rotation ledger no longer lists (entry {digest}) — "
                    f"audit.chain was truncated, pruned or deleted")

    # The tail checkpoint: the chain cannot speak for records removed from the
    # end, so compare against what the last write recorded.
    head = read_head()
    tail_note = ""
    if head is None and expects_head:
        # The log says, inside its own chain, that it is checkpointed. A
        # missing audit.head is therefore a deletion, not an old install —
        # and deleting it is step two of truncating the tail.
        return False, n, ("the log records that it is checkpointed, but "
                          "audit.head is missing — it was deleted")
    if head is not None:
        if not head_ok(head):
            return False, n, ("the tail checkpoint (audit.head) does not verify "
                              "against the signing key — it was rewritten")
        want_n, want_last = int(head.get("count", 0)), head.get("last")
        if n < want_n or (want_last and prev != want_last):
            return False, n, (
                f"the log was truncated: the last write recorded {want_n} records "
                f"ending {want_last}, the file has {n} ending {prev}")
    elif n:
        tail_note = " (no tail checkpoint — records removed from the end of the "
        tail_note += "file would not be detected; audit.head is missing)"

    msg = f"chain intact across {n} records"
    if len(files) > 1:
        msg += f" in {len(files)} segments"
    if badsig:
        return False, n, f"{msg}, but {badsig} signature(s) do not verify"
    # Unsigned records while signing is configured are a failure, not a note.
    # Otherwise the downgrade is free: delete the checkpoint, strip every
    # signature, rewrite the history, recompute the chain — and a log that
    # tolerates unsigned records calls the result intact. A log that genuinely
    # predates signing gets the same verdict, and the fix for it is to rotate,
    # which is what an operator turning signing on should do anyway.
    if unsigned and signing.mode() != signing.ALG_NONE:
        return False, n, (
            f"{msg}, but {unsigned} of them carry no signature while signing is "
            f"on — either they predate it (rotate the log) or the signatures "
            f"were stripped")
    if unsigned and unsigned < n:
        msg += f" ({n - unsigned} signed, {unsigned} unsigned)"
    elif not unsigned and n:
        msg += " (all signed)"
    return True, n, msg + tail_note
