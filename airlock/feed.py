"""Updatable indicator feed — `airlock update`.

Exfil collectors, injection phrasings and bad-server fingerprints rot the way
antivirus signatures rot. A firewall whose indicators ship once with the binary
is out of date the week after release, so indicators live in a versioned feed
that updates independently of the code — and that is also the honest basis for
a subscription: the engine is free, the freshness is the product.

Feed format (JSON), designed so a detached signature can be added without a
format change:

    {
      "version": 3,
      "updated": "2026-08-20",
      "patterns": [
        {"id": "exfil.collector", "severity": "high",
         "regex": "webhook\\\\.site|requestbin", "why": "known collector"}
      ],
      "block_hosts": ["evil.example"],
      "signature": {"alg": "hmac-sha256", "value": "..."}   # optional
    }

THE FLOOR
---------
Two sets of indicators always load and can never be removed by an update:
scan.py's compiled patterns, and the bundled `data/feed.json` that ships in the
wheel. A downloaded feed is merged ON TOP of both — it can add indicators and
raise a severity, never lower one and never delete one.

This matters more than it sounds. Half the shipped indicators (tokens, paste
sites, encoded blobs, install-from-URL) live in the bundled feed rather than in
scan.py, so "built-ins are safe" was only half a guarantee: an update that
redefined `secrets.token` to match nothing switched that detection off. The
floor closes that. A hostile feed can make Airlock noisy; it cannot make it
blind.

SIGNATURES
----------
An unsigned feed is refused by default. A tool that exists because people
install code they have not read does not get to fetch its own detection rules
over plain HTTPS and trust whatever comes back. Set AIRLOCK_FEED_KEY (or
--allow-unsigned, deliberately, for a feed you host yourself).
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import time
import urllib.request
from pathlib import Path

from . import config

DEFAULT_URL = os.environ.get(
    "AIRLOCK_FEED_URL",
    "https://raw.githubusercontent.com/airlock-agent/indicators/main/feed.json")
BUNDLED = config.PKG / "data" / "feed.json"


def feed_path() -> Path:
    return config.home() / "feed.json"


def _read(p: Path) -> dict | None:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("patterns"), list):
            d["_path"] = str(p)
            return d
    except Exception:
        pass
    return None


def bundled() -> dict:
    """The floor: what shipped in the wheel. Never overridden by an update."""
    return _read(BUNDLED) or {"version": 0, "patterns": [], "_path": "(none)"}


def downloaded() -> dict | None:
    return _read(feed_path())


def load() -> dict:
    """What `airlock update --status` reports: the downloaded feed if there is
    one, else the bundled floor."""
    return downloaded() or bundled()


_SEV_RANK = {"low": 0, "med": 1, "high": 2}


def compiled() -> list[tuple[str, str, re.Pattern, str]]:
    """Every feed pattern, floor first, in scan.py's tuple shape.

    The bundled patterns are emitted unconditionally. A downloaded pattern with
    the same id is emitted ALONGSIDE the bundled one, not instead of it — and if
    it claims a lower severity than the floor, the floor's severity is kept.
    Bad regexes are skipped, not fatal.
    """
    out: list[tuple[str, str, re.Pattern, str]] = []
    floor_sev: dict[str, str] = {}

    def emit(entry: dict, is_floor: bool) -> None:
        pid = str(entry.get("id", "feed.unknown"))
        try:
            rx = re.compile(entry["regex"], re.I)
        except Exception:
            return
        sev = entry.get("severity", "med")
        if sev not in _SEV_RANK:
            sev = "med"
        if is_floor:
            floor_sev[pid] = sev
        elif pid in floor_sev and _SEV_RANK[sev] < _SEV_RANK[floor_sev[pid]]:
            sev = floor_sev[pid]      # an update may raise severity, never lower it
        out.append((pid, sev, rx, entry.get("why", "")))

    for e in bundled().get("patterns") or []:
        emit(e, True)
    d = downloaded()
    if d:
        for e in d.get("patterns") or []:
            emit(e, False)
    return out


def block_hosts() -> list[str]:
    """Union of the floor and any update — an update cannot un-block a host."""
    hosts = {str(h).lower() for h in (bundled().get("block_hosts") or [])}
    d = downloaded()
    if d:
        hosts |= {str(h).lower() for h in (d.get("block_hosts") or [])}
    return sorted(hosts)


def signing_key() -> bytes | None:
    k = os.environ.get("AIRLOCK_FEED_KEY", "").strip()
    if not k:
        return None
    try:
        return bytes.fromhex(k)
    except ValueError:
        return k.encode()


def sign_payload(data: dict, key: bytes) -> str:
    body = {k: v for k, v in data.items() if k not in ("signature", "_path")}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


def _verify(data: dict, key: bytes | None) -> tuple[bool, str]:
    """Return (acceptable, description)."""
    sig = data.get("signature") or {}
    if not sig:
        return False, "the feed is not signed"
    if not key:
        return False, ("the feed is signed but no key is configured — "
                       "set AIRLOCK_FEED_KEY to verify it")
    if hmac.compare_digest(sign_payload(data, key), sig.get("value", "")):
        return True, "signature OK"
    return False, "SIGNATURE MISMATCH"


def update(src: str | None = None, *, timeout: float = 20.0,
           allow_unsigned: bool = False) -> tuple[bool, str]:
    """Fetch a feed from a URL or a local file. Returns (ok, message).

    Refuses an unsigned or unverifiable feed unless the caller explicitly opts
    out. The detection rules of a supply-chain tool are themselves a supply
    chain; fetching them unauthenticated would be the exact failure this project
    is about.
    """
    src = src or DEFAULT_URL
    try:
        if "://" in src and not src.startswith("file://"):
            req = urllib.request.Request(src, headers={"User-Agent": "airlock"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8")
        else:
            raw = Path(src.replace("file://", "")).read_text(encoding="utf-8")
    except Exception as e:
        return False, f"could not fetch {src}: {e}"

    try:
        data = json.loads(raw)
    except Exception as e:
        return False, f"{src} is not valid JSON: {e}"
    if not isinstance(data, dict):
        return False, f"{src} is not a feed: expected an object, got {type(data).__name__}"
    if not isinstance(data.get("patterns"), list):
        return False, (f"{src} is not a feed: it has no `patterns` list "
                       f"(keys present: {', '.join(sorted(data)[:6]) or 'none'})")
    if not isinstance(data.get("version"), int):
        return False, f"{src} is not a feed: `version` must be an integer"

    ok, verdict = _verify(data, signing_key())
    if not ok:
        if not allow_unsigned:
            return False, (f"refusing to install: {verdict}. Pass --allow-unsigned "
                           f"if you host this feed yourself and accept that.")
        verdict += " (accepted via --allow-unsigned)"

    cur = load().get("version", 0)
    new = data.get("version", 0)
    if new < cur:
        return False, f"feed version {new} is older than the installed {cur}"

    bad = [str(p.get("id")) for p in data["patterns"]
           if not isinstance(p, dict) or not _compiles(p.get("regex", ""))]
    if bad:
        return False, (f"feed contains {len(bad)} uncompilable pattern(s): "
                       f"{', '.join(bad[:5])}")

    p = feed_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)
    return True, (f"feed v{new} installed ({len(data['patterns'])} indicators, "
                  f"{len(data.get('block_hosts') or [])} hosts) — {verdict}")


def _compiles(rx: str) -> bool:
    try:
        re.compile(rx)
        return True
    except Exception:
        return False


def status() -> str:
    total = len(compiled())
    b = bundled()
    d = downloaded()
    if not d:
        return (f"indicators: {total} active — bundled floor v{b.get('version', 0)} "
                f"only (run `airlock update`)")
    age = ""
    if d.get("updated"):
        try:
            t = time.mktime(time.strptime(d["updated"], "%Y-%m-%d"))
            age = f", {int((time.time() - t) / 86400)}d old"
        except Exception:
            pass
    signed = "signed" if (d.get("signature") or {}) else "unsigned"
    return (f"indicators: {total} active — feed v{d['version']} ({signed}{age}) "
            f"over bundled floor v{b.get('version', 0)}")
