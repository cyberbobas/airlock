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
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import config

# Where a hosted feed will live once the indicators repo is published. Until
# then FEED_PUBLISHED is False, so a bare `airlock update` says so instead of
# firing an HTTP request at a repo that 404s. Flip this to True the day the
# indicators repo goes live.
HOSTED_FEED_URL = "https://raw.githubusercontent.com/cyberbobas/indicators/main/feed.json"
FEED_PUBLISHED = False
BUNDLED = config.PKG / "data" / "feed.json"


def default_source() -> str | None:
    """The feed to fetch when none is named: an explicit env URL, else the
    hosted feed once it exists, else nothing (not yet published)."""
    env = os.environ.get("AIRLOCK_FEED_URL", "").strip()
    if env:
        return env
    return HOSTED_FEED_URL if FEED_PUBLISHED else None


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
    src = src or default_source()
    if not src:
        return False, ("no hosted indicator feed is published yet. Airlock runs "
                       "fully on its bundled floor; to install a feed, pass a URL "
                       "or file (or set AIRLOCK_FEED_URL) — `airlock update "
                       "./feed.json`.")
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

    for entry in data["patterns"]:
        if not isinstance(entry, dict):
            return False, "feed contains a pattern that is not an object"
        ok_rx, why = _pattern_ok(str(entry.get("regex", "")))
        if not ok_rx:
            return False, (f"refusing to install: pattern "
                           f"{entry.get('id', '(unnamed)')!r} {why}")

    p = feed_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)
    return True, (f"feed v{new} installed ({len(data['patterns'])} indicators, "
                  f"{len(data.get('block_hosts') or [])} hosts) — {verdict}")


# A pattern from a feed runs on every gated call, in-process, with no way to
# interrupt it: Python's `re` has no timeout. `(a+)+$` against forty a's and a
# "!" backtracks for longer than anyone will wait, and the proxy answering that
# call simply never answers — the agent hangs. So a feed that is merely
# *installable* is not enough: a pattern has to be shown to terminate quickly
# on inputs designed to make it not.
_CANARIES = [
    "a" * 40 + "!",
    "ab" * 24 + "!",
    "0" * 48 + "!",
    ("x" * 8 + "/") * 8 + "!",
    "https://" + "a" * 40 + "@" + "b" * 24 + "!",
    " " * 48 + "!",
]
_CANARY_BUDGET = 2.0           # wall clock for one pattern's probes, in a child
def _unbounded_after(rx: str, i: int) -> bool:
    """Is the token at rx[i:] an unbounded quantifier (+, *, {n,})?"""
    if i >= len(rx):
        return False
    if rx[i] in "+*":
        return True
    return bool(re.match(r"\{\d*,\}", rx[i:]))


def _variable_after(rx: str, i: int) -> bool:
    """Any quantifier that is not a fixed `{n}` — one that leaves the matcher a
    choice about how much to consume. `(a{1,3})+` is exponential for exactly
    that reason, even though the inner bound is finite."""
    if i >= len(rx):
        return False
    if rx[i] in "+*?":
        return True
    m = re.match(r"\{(\d*)(,?)(\d*)\}", rx[i:])
    return bool(m and m.group(2))


_GROUP_PREFIX = re.compile(r"^\?(?::|=|!|<=|<!|<[A-Za-z_]\w*>|P<[A-Za-z_]\w*>|[aiLmsux]*[:)])")


def _body_has_unbounded(body: str) -> bool:
    """Unbounded quantifier in this group body, ignoring escapes and classes.

    `[A-Za-z0-9+/]` contains a literal `+` that quantifies nothing; counting it
    would reject the bundled base64 indicator. The `?` in a `(?:...)` group is
    a modifier, not a quantifier, so the prefix comes off first — otherwise
    every non-capturing group in the feed looks exponential.
    """
    body = _GROUP_PREFIX.sub("", body)
    i, in_class = 0, False
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif _variable_after(body, i):
            return True
        i += 1
    return False


def _nested_unbounded(rx: str) -> bool:
    """An unbounded quantifier applied to a group that contains another one.

    That is the shape that backtracks exponentially — `(a+)+`, `(([a-z])+.)+`.
    A *fixed* inner repetition is fine: `(?:\\u00[0-9a-f]{2}){4,}` consumes
    exactly six characters per round, so there is nothing to backtrack over.
    """
    stack, i, in_class = [], 0, False
    while i < len(rx):
        ch = rx[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            start = stack.pop()
            if _unbounded_after(rx, i + 1) and _body_has_unbounded(rx[start + 1:i]):
                return True
        i += 1
    return False


def _pattern_ok(rx: str) -> tuple[bool, str]:
    """Return (acceptable, why not). Compiles, then times it under attack."""
    if not rx:
        return False, "has an empty regex"
    try:
        c = re.compile(rx, re.I)
    except Exception as e:
        return False, f"does not compile: {e}"
    if _nested_unbounded(rx):
        return False, ("nests a quantifier inside a quantified group, which can "
                       "backtrack exponentially — rewrite it without the nesting")
    return _time_it(rx)


def _time_it(rx: str) -> tuple[bool, str]:
    """Run the probes in a child process.

    The syntactic check catches the classic shapes, but `re` cannot be
    interrupted: a pattern it misses would wedge `airlock update` exactly the
    way it would have wedged the gate. A child can be killed; this one is.
    """
    src = ("import re, sys, json\n"
           "rx = json.loads(sys.stdin.read())\n"
           "c = re.compile(rx, re.I)\n"
           "for probe in %r:\n"
           "    c.search(probe)\n" % (_CANARIES,))
    try:
        r = subprocess.run([sys.executable, "-c", src], input=json.dumps(rx),
                           capture_output=True, text=True, timeout=_CANARY_BUDGET)
    except subprocess.TimeoutExpired:
        return False, (f"did not finish {len(_CANARIES)} short probes in "
                       f"{_CANARY_BUDGET:g}s — a pattern this slow stalls every "
                       f"gated call")
    except Exception as e:
        return False, f"could not be timed: {e}"
    if r.returncode != 0:
        return False, f"raised while matching: {(r.stderr or '').strip()[-120:]}"
    return True, ""


def status() -> str:
    total = len(compiled())
    b = bundled()
    d = downloaded()
    if not d:
        return (f"indicators: {total} active — bundled floor v{b.get('version', 0)} "
                f"(no hosted feed published yet; `airlock update <url|file>` "
                f"installs one you point it at)")
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
