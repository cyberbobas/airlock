"""Audit export — get the decisions into whatever the buyer already runs.

A security team does not adopt a tool that only speaks its own JSON. CEF is what
ArcSight/Splunk ingest without a custom parser; RFC5424 is what every syslog
collector takes; JSONL is for everyone else.
"""
from __future__ import annotations
import json
import socket
import time
from pathlib import Path

from . import audit

_SEVERITY = {"block": 8, "hold": 8, "ask": 5, "flag": 4, "allow": 2,
             "admit": 2, "change": 6}
_CEF_ESCAPE = str.maketrans({"\\": r"\\", "|": r"\|", "=": r"\="})


def _rows(days: float, path: Path | None = None):
    cutoff = time.time() - days * 86400 if days else 0
    from .report import _parse_ts
    for p in ([Path(path)] if path else audit.rotated_files()):
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if cutoff and _parse_ts(rec.get("ts", "")) < cutoff:
                continue
            yield rec


def _esc(v) -> str:
    return str(v or "").translate(_CEF_ESCAPE).replace("\n", " ")


def to_cef(rec: dict) -> str:
    eff = rec.get("effective") or rec.get("decision") or rec.get("event") or "?"
    sev = _SEVERITY.get(eff, 3)
    name = f"{rec.get('event','decision')}:{eff}"
    ext = {
        "rt": rec.get("ts", ""),
        "act": eff,
        "outcome": eff,
        "cs1Label": "tool", "cs1": _esc(rec.get("tool")),
        "cs2Label": "server", "cs2": _esc(rec.get("server")),
        "cs3Label": "reason", "cs3": _esc(rec.get("reason")),
        "cs4Label": "resource", "cs4": _esc(rec.get("resource")),
        "cs5Label": "chainDigest", "cs5": _esc(rec.get("h")),
        "suser": _esc(rec.get("session")),
        "cat": _esc(rec.get("source")),
    }
    if rec.get("flags"):
        ext["cs6Label"] = "scanFlags"
        ext["cs6"] = _esc(",".join(f.get("id", "?") for f in rec["flags"]))
    body = " ".join(f"{k}={v}" for k, v in ext.items() if v)
    return (f"CEF:0|Airlock|airlock|{audit.__dict__.get('__version__', '0.3.0')}|"
            f"{_esc(rec.get('event','decision'))}|{_esc(name)}|{sev}|{body}")


def to_syslog(rec: dict, host: str | None = None, app: str = "airlock") -> str:
    """RFC5424. Priority = local0 (16) * 8 + severity."""
    eff = rec.get("effective") or rec.get("decision") or "?"
    sev = {"block": 3, "hold": 3, "ask": 4, "flag": 5}.get(eff, 6)  # err/warn/notice/info
    pri = 16 * 8 + sev
    host = host or socket.gethostname()
    ts = rec.get("ts", "") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sd = (f'[airlock@0 event="{_esc(rec.get("event"))}" effective="{_esc(eff)}" '
          f'tool="{_esc(rec.get("tool"))}" server="{_esc(rec.get("server"))}" '
          f'resource="{_esc(rec.get("resource"))}" digest="{_esc(rec.get("h"))}"]')
    return f"<{pri}>1 {ts} {host} {app} - - {sd} {_esc(rec.get('reason'))}"


FORMATS = ("jsonl", "cef", "syslog")


def export(fmt: str = "jsonl", *, days: float = 0, path: Path | None = None):
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {FORMATS}")
    for rec in _rows(days, path):
        if fmt == "jsonl":
            yield json.dumps(rec, ensure_ascii=False)
        elif fmt == "cef":
            yield to_cef(rec)
        else:
            yield to_syslog(rec)
