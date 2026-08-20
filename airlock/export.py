"""Audit export — get the decisions into whatever the buyer already runs.

A security team does not adopt a tool that only speaks its own JSON. CEF is what
ArcSight/Splunk ingest without a custom parser; RFC5424 is what every syslog
collector takes; JSONL is for everyone else.
"""
from __future__ import annotations
import json
import re
import socket
import time
from pathlib import Path

from . import audit


def _version() -> str:
    """The real package version. A SIEM record that misstates which build made
    the decision is evidence about nothing in particular."""
    from . import __version__
    return __version__


_SEVERITY = {"block": 8, "hold": 8, "ask": 5, "flag": 4, "allow": 2,
             "admit": 2, "change": 6}
# The one sequence that can be mistaken for the header of a structured-data
# element. Escaping `"` `\` `]` satisfies RFC5424 and a compliant parser, but a
# regex-based SIEM pipeline scanning for `[airlock@` finds a second "element"
# inside an escaped value. Neutralising just the marker leaves every other
# bracket in the text alone.
_SD_MARKER = re.compile(r"\[(airlock@)")

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
    """CEF: backslash-escape `\\`, `=` and `|`; keep it on one line."""
    return str(v or "").translate(_CEF_ESCAPE).replace("\n", " ").replace("\r", " ")


def _sd(v) -> str:
    """RFC5424 PARAM-VALUE (§6.3.3): escape `\\`, `"` and `]` — those three and
    nothing else.

    Reusing the CEF escaper here escaped `=`, which RFC5424 does not define,
    and left `"` and `]` alone, which it requires. A file path containing
    `"] [airlock@0 effective="allow"` therefore closed the structured-data
    element and opened a second one the caller controlled outright: a SIEM
    parsed two elements, the second forged. Evidence that a payload can extend
    is not evidence.
    """
    out = str(v or "")
    out = out.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    # Escaping alone satisfies the RFC and any compliant parser. It does not
    # satisfy the regex-based SIEM pipelines that are just as common: those scan
    # for `[airlock@` and find a second "element" sitting inside an escaped
    # value. Neutralising that one marker — and nothing else — closes it without
    # touching any other bracket in the text.
    out = out.replace("[airlock@", "(airlock@")
    return "".join(" " if ch < " " or ch == "\x7f" else ch for ch in out)


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
    return (f"CEF:0|Airlock|airlock|{_version()}|"
            f"{_esc(rec.get('event','decision'))}|{_esc(name)}|{sev}|{body}")


def _msg(v) -> str:
    """The free-text half of a syslog line.

    RFC5424 says MSG is not parsed as structured data, and a compliant parser
    reads it that way. Plenty of SIEM pipelines are regexes rather than parsers,
    and a reason containing `[airlock@0 effective="allow"` gave those a second
    element to find — the same forgery that was fixed one field over, just moved
    into MSG. Brackets are neutralised here; the exact text is still carried,
    correctly escaped, as `reason=` inside the real SD element.
    """
    return (str(v or "").replace("\\", "/").replace("[", "(").replace("]", ")")
            .replace("\n", " ").replace("\r", " ").replace("\x00", ""))


def to_syslog(rec: dict, host: str | None = None, app: str = "airlock") -> str:
    """RFC5424. Priority = local0 (16) * 8 + severity."""
    eff = rec.get("effective") or rec.get("decision") or "?"
    sev = {"block": 3, "hold": 3, "ask": 4, "flag": 5}.get(eff, 6)  # err/warn/notice/info
    pri = 16 * 8 + sev
    host = host or socket.gethostname()
    ts = rec.get("ts", "") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sd = (f'[airlock@0 event="{_sd(rec.get("event"))}" effective="{_sd(eff)}" '
          f'tool="{_sd(rec.get("tool"))}" server="{_sd(rec.get("server"))}" '
          f'resource="{_sd(rec.get("resource"))}" reason="{_sd(rec.get("reason"))}" '
          f'digest="{_sd(rec.get("h"))}"]')
    # MSG is free text and a compliant parser does not read structured data out
    # of it — but plenty of SIEM pipelines are regexes, and a reason containing
    # `[airlock@0 effective="allow"` handed those a second element to find. That
    # is the same forgery that was fixed one field over, moved into MSG.
    # Brackets are neutralised here; the exact text is carried, correctly
    # escaped, as `reason=` inside the real SD element above.
    msg = "".join(" " if ch < " " else ch for ch in str(rec.get("reason") or ""))
    msg = msg.replace("[", "(").replace("]", ")")
    return f"<{pri}>1 {_sd(ts)} {_sd(host)} {app} - - {sd} {msg}"


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
