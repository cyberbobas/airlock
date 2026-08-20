"""Skill/toolset admission (plane 4, stage 0) — pin-on-first-use, hold-on-change.

We hash a server's advertised toolset (names + descriptions + schemas). The
first time we see it we PIN it (trust-on-first-use). If the hash later changes,
that is a silent-update / rug-pull signal.

A detection that auto-accepts is not a control. So a changed toolset puts the
server in HELD state: the old pin stays authoritative, the new hash is parked as
`pending`, and every call is blocked until a human runs

    airlock pins approve <server-id>     # adopt the new toolset
    airlock pins reject  <server-id>     # keep the old pin, keep holding

This is the "calls held" cell of threat-model row 3, which previously existed
only in the table.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path

from .audit import home

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


def toolset_hash(tools: list[dict]) -> str:
    norm = [
        {"name": t.get("name"),
         "description": t.get("description", ""),
         "schema": t.get("inputSchema") or t.get("input_schema") or {}}
        for t in sorted(tools, key=lambda t: t.get("name", ""))
    ]
    blob = json.dumps(norm, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def _pins_path() -> Path:
    return home() / "pins.json"


def _lock_path() -> Path:
    return home() / "pins.lock"


class _Lock:
    """Cross-process lock so two proxies never clobber each other's pins."""

    def __enter__(self):
        self.f = open(_lock_path(), "a+")
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        self.f.close()
        return False


def load() -> dict:
    p = _pins_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save(data: dict) -> bool:
    """Atomic replace. Returns False if the store could not be written.

    A crash mid-write must not leave an empty pin file — an empty pin file
    silently re-TOFUs every server. A FULL DISK must not raise either: this is
    called from the proxy's server pump, where an exception killed the thread
    and the agent simply stopped receiving responses. A disk problem should
    degrade rug-pull detection, not hang the tool.
    """
    p = _pins_path()
    tmp = p.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        os.replace(tmp, p)
        return True
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# A hold decided in this process, whether or not it reached the disk.
#
# check_toolset() set held=True in memory and saved; is_held() then re-read the
# file. With an unwritable $AIRLOCK_HOME the save failed, the file still said
# held=False, and a rug pull sailed through — detection had happened and then
# evaporated because it could not be written down. Noticing must not depend on
# being able to record that you noticed.
_HELD_NOW: dict[str, dict] = {}


def check_toolset(server_id: str, tools: list[dict], flags: list[dict],
                  hold_on_flag: bool = False):
    """Return (status, pin). status in {'new','unchanged','changed','held'}.

    hold_on_flag makes a first sighting behave like a drift: the toolset is
    pinned, and every call to it is held until a human approves. The scanner
    found tool poisoning at admission, recorded three high-severity findings
    and admitted the server anyway — detection that changes no decision is
    detection that narrows nothing, which is the opposite of what the static
    stage is for.
    """
    h = toolset_hash(tools)
    names = sorted(t.get("name", "?") for t in tools)
    with _Lock():
        data = load()
        prev = data.get(server_id)

        if prev is None:
            pin = {"hash": h, "tools": names, "flagged": bool(flags),
                   "pinned_at": _now(), "held": bool(hold_on_flag)}
            if hold_on_flag:
                pin["pending"] = {"hash": h, "tools": names, "flagged": True,
                                  "seen_at": _now(), "poisoned": True}
            data[server_id] = pin
            pin["persisted"] = save(data)
            if hold_on_flag:
                _HELD_NOW[server_id] = pin
            return "new", pin

        if prev.get("hash") == h:
            # Same toolset as the trusted pin. If it was held on an earlier
            # drift and the server reverted, the hold is satisfied — but a hold
            # placed because the descriptions themselves scanned high is not
            # satisfied by the server staying exactly as poisoned as it was.
            if prev.get("held") and (prev.get("pending") or {}).get("poisoned"):
                _HELD_NOW[server_id] = prev
                return "held", prev
            if prev.get("held"):
                prev["held"] = False
                prev.pop("pending", None)
                prev["persisted"] = save(data)
            _HELD_NOW.pop(server_id, None)
            return "unchanged", prev

        if prev.get("held") and (prev.get("pending") or {}).get("hash") == h:
            _HELD_NOW[server_id] = prev
            return "held", prev            # already flagged, still not approved

        # New drift: park it, keep the OLD hash authoritative, start holding.
        prev.setdefault("history", []).append(
            {"hash": prev.get("hash"), "tools": prev.get("tools"), "until": _now()})
        prev["pending"] = {"hash": h, "tools": names, "flagged": bool(flags),
                           "seen_at": _now()}
        prev["held"] = True
        prev["persisted"] = save(data)
        _HELD_NOW[server_id] = prev
        return "changed", prev


def is_held(server_id: str) -> tuple[bool, str]:
    # Disk first: it is the fresher, richer copy — `approve` and `reject` write
    # there, possibly from another process. Memory is only the fallback for a
    # hold this process decided but could not persist.
    pin = load().get(server_id) or {}
    if not pin.get("held"):
        pin = _HELD_NOW.get(server_id) or pin
    if not pin.get("held"):
        return False, ""
    pend = pin.get("pending") or {}
    added = sorted(set(pend.get("tools") or []) - set(pin.get("tools") or []))
    detail = f" new tools: {', '.join(added)}" if added else ""
    if pend.get("poisoned") and not pend.get("rejected"):
        return True, (f"a tool description on this server carries an injection "
                      f"or exfiltration indicator — held for review "
                      f"(`airlock pins approve {server_id}` if you have read it)"
                      f"{detail}")
    if pend.get("rejected"):
        return True, (f"toolset was reviewed and REJECTED — calls stay blocked "
                      f"until the server reverts, or you override with "
                      f"`airlock pins approve {server_id}`.{detail}")
    return True, (f"toolset changed since it was pinned — held pending review "
                  f"(airlock pins approve {server_id}).{detail}")


def approve(server_id: str) -> str:
    _HELD_NOW.pop(server_id, None)      # a human ruled; the in-process fallback is stale
    with _Lock():
        data = load()
        pin = data.get(server_id)
        if not pin:
            return f"no pin for '{server_id}'"
        pend = pin.pop("pending", None)
        if not pend:
            if not pin.get("held"):
                return f"'{server_id}' was not held"
            pin["held"] = False
            if not save(data):
                return f"could not write the pin store — '{server_id}' is unchanged"
            return f"'{server_id}' released (there was no pending toolset to adopt)"
        pin["hash"] = pend["hash"]
        pin["tools"] = pend["tools"]
        pin["flagged"] = pend.get("flagged", False)
        pin["held"] = False
        pin["pinned_at"] = _now()
        if not save(data):
            return f"could not write the pin store — '{server_id}' is unchanged"
        return f"'{server_id}' re-pinned to the new toolset ({len(pin['tools'])} tools)"


def reject(server_id: str) -> str:
    _HELD_NOW.pop(server_id, None)      # a human ruled; the in-process fallback is stale
    with _Lock():
        data = load()
        pin = data.get(server_id)
        if not pin:
            return f"no pin for '{server_id}'"
        pend = pin.get("pending")
        if not pend:
            # Nothing was pending, so there is nothing to reject. Holding anyway
            # turned a mistyped server id into a self-inflicted outage: every
            # call to a perfectly healthy server refused until it happened to
            # advertise its toolset again.
            return f"'{server_id}' has no pending change — nothing to reject"
        # Keep the rejected toolset on record. Discarding it lost the memory of
        # WHAT was refused: the server offering the same set again read as a
        # fresh drift, and `approve` afterwards found nothing to adopt and
        # quietly un-held the server instead. A rejection has to be remembered
        # to mean anything.
        pend["rejected"] = True
        pin["held"] = True          # stays held: the server still ships the new set
        if not save(data):
            return f"could not write the pin store — '{server_id}' is unchanged"
        return f"'{server_id}' rejected — calls stay blocked until it reverts or you approve"


def forget(server_id: str) -> str:
    _HELD_NOW.pop(server_id, None)      # a human ruled; the in-process fallback is stale
    with _Lock():
        data = load()
        if data.pop(server_id, None) is None:
            return f"no pin for '{server_id}'"
        if not save(data):
            return f"could not write the pin store — '{server_id}' is unchanged"
    # Outside the pin lock: contracts keeps its own.
    try:
        from . import contracts
        dropped = contracts.unenforce(server_id)
    except Exception:
        dropped = False
    note = (" — its contract is no longer enforced either "
            "(`airlock contracts show` still has it)") if dropped else ""
    return f"'{server_id}' unpinned (next run re-TOFUs it){note}"
