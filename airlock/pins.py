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


def save(data: dict) -> None:
    """Atomic replace — a crash mid-write must not leave an empty pin file
    (an empty pin file silently re-TOFUs every server)."""
    p = _pins_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.replace(tmp, p)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def check_toolset(server_id: str, tools: list[dict], flags: list[dict]):
    """Return (status, pin). status in {'new','unchanged','changed','held'}."""
    h = toolset_hash(tools)
    names = sorted(t.get("name", "?") for t in tools)
    with _Lock():
        data = load()
        prev = data.get(server_id)

        if prev is None:
            pin = {"hash": h, "tools": names, "flagged": bool(flags),
                   "pinned_at": _now(), "held": False}
            data[server_id] = pin
            save(data)
            return "new", pin

        if prev.get("hash") == h:
            # Same toolset as the trusted pin. If it was held on an earlier
            # drift and the server reverted, the hold is satisfied.
            if prev.get("held"):
                prev["held"] = False
                prev.pop("pending", None)
                save(data)
            return "unchanged", prev

        if prev.get("held") and (prev.get("pending") or {}).get("hash") == h:
            return "held", prev            # already flagged, still not approved

        # New drift: park it, keep the OLD hash authoritative, start holding.
        prev.setdefault("history", []).append(
            {"hash": prev.get("hash"), "tools": prev.get("tools"), "until": _now()})
        prev["pending"] = {"hash": h, "tools": names, "flagged": bool(flags),
                           "seen_at": _now()}
        prev["held"] = True
        save(data)
        return "changed", prev


def is_held(server_id: str) -> tuple[bool, str]:
    pin = load().get(server_id) or {}
    if not pin.get("held"):
        return False, ""
    pend = pin.get("pending") or {}
    added = sorted(set(pend.get("tools") or []) - set(pin.get("tools") or []))
    detail = f" new tools: {', '.join(added)}" if added else ""
    return True, (f"toolset changed since it was pinned — held pending review "
                  f"(airlock pins approve {server_id}).{detail}")


def approve(server_id: str) -> str:
    with _Lock():
        data = load()
        pin = data.get(server_id)
        if not pin:
            return f"no pin for '{server_id}'"
        pend = pin.pop("pending", None)
        if not pend:
            pin["held"] = False
            save(data)
            return f"'{server_id}' was not held"
        pin["hash"] = pend["hash"]
        pin["tools"] = pend["tools"]
        pin["flagged"] = pend.get("flagged", False)
        pin["held"] = False
        pin["pinned_at"] = _now()
        save(data)
        return f"'{server_id}' re-pinned to the new toolset ({len(pin['tools'])} tools)"


def reject(server_id: str) -> str:
    with _Lock():
        data = load()
        pin = data.get(server_id)
        if not pin:
            return f"no pin for '{server_id}'"
        pin.pop("pending", None)
        pin["held"] = True          # stays held: the server still ships the new set
        save(data)
        return f"'{server_id}' rejected — calls stay blocked until it reverts or you approve"


def forget(server_id: str) -> str:
    with _Lock():
        data = load()
        if data.pop(server_id, None) is None:
            return f"no pin for '{server_id}'"
        save(data)
        return f"'{server_id}' unpinned (next run re-TOFUs it)"
