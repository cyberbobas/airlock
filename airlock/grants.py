"""`airlock allow` — turn "it blocked me" into a reviewed grant, in one command.

This is the load-bearing piece of the product's usability. Someone who hits a
block and has to go read YAML does not tune the policy; they uninstall. So the
path from a refusal to a working setup is: read the last gated call from the
audit log, propose the narrowest grant that would have let it through, show the
human exactly what they are about to permit, write it into `grants:`.

"Gated" means blocked *or* asked. The friction people actually complain about is
not the rare block — it is being prompted about the same harmless thing fourteen
times a day. `airlock allow` has to answer "stop asking me this" or the prompts
train people to click through, which is worse than no gate at all.

A grant can never lift an absolute block rule (see policy.decide) — so offering
this is safe even when someone runs it without reading.
"""
from __future__ import annotations
import json
import os
import time
from pathlib import Path

import yaml

from . import audit, config


GATED = ("block", "ask")


def _gated_events(limit: int = 2000) -> list[dict]:
    p = audit.audit_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("event") == "decision" and r.get("effective") in GATED:
            out.append(r)
    return out


def last_gated() -> dict | None:
    ev = _gated_events()
    return ev[-1] if ev else None


def recent_gated(n: int = 10) -> list[dict]:
    """Most recent distinct gated calls, most-repeated first.

    Ranked by how often it happened, because the one you were interrupted about
    twelve times is the one you actually want to grant.
    """
    groups: dict[tuple, dict] = {}
    for r in _gated_events():
        key = (r.get("tool"), r.get("effective"), r.get("reason", "").split(" (")[0])
        g = groups.setdefault(key, {"count": 0, "last": r, "resources": []})
        g["count"] += 1
        g["last"] = r
        res = r.get("resource")
        if res and res not in g["resources"]:
            g["resources"].append(res)
    ranked = sorted(groups.values(), key=lambda g: (-g["count"], g["last"].get("ts", "")))
    out = []
    for g in ranked[:n]:
        e = dict(g["last"])
        e["_count"] = g["count"]
        e["_resources"] = g["resources"][:5]
        out.append(e)
    return out


def common_parent(paths: list[str]) -> str | None:
    """The tightest directory covering everything seen — so granting a tool that
    was asked about twelve files does not have to be twelve grants."""
    paths = [p for p in paths if p and "/" in p and not p.startswith("http")]
    if not paths:
        return None
    parts = [os.path.dirname(p).split("/") for p in paths]
    common: list[str] = []
    for seg in zip(*parts):
        if len(set(seg)) == 1:
            common.append(seg[0])
        else:
            break
    d = "/".join(common)
    return d if d and d != "/" else None


def propose(event: dict) -> dict | None:
    """The narrowest grant that would have allowed this call.

    Narrow means: this tool, and — when the call was about a concrete path or
    host — that directory or that host, not a wildcard.
    """
    tool = event.get("tool") or ""
    if not tool:
        return None
    resource = (event.get("resource") or "").strip()
    grant = {"tool": tool}
    seen = event.get("_resources") or ([resource] if resource else [])
    parent = common_parent(seen)
    if parent:
        grant["match"] = f"{parent}/*"
    elif resource and resource not in ("other", ""):
        if resource.startswith("http") or ("." in resource and " " not in resource
                                           and "/" not in resource):
            grant["match"] = f"*{resource}*"
    grant["reason"] = (f"allowed by {os.environ.get('USER', 'you')} on "
                       f"{time.strftime('%Y-%m-%d')}")
    grant["added"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return grant


def hard_blocked(pol, grant: dict) -> str | None:
    """Would an absolute block rule still refuse this? Then say so up front
    rather than writing a grant that quietly does nothing."""
    probe = grant.get("match", "").replace("*", "") or grant["tool"]
    d = pol.decide(grant["tool"], {"path": probe} if "/" in probe else {"q": probe})
    if d.action == "block" and (d.rule is None or d.rule >= 0):
        return d.reason
    return None


def target_policy(pol) -> Path:
    """Which file `allow` may write to.

    Never the bundled profile — that lives in site-packages and is shared. If
    the active policy is a profile, materialise a personal copy first.
    """
    if pol.source.startswith("bundled"):
        dst = config.user_policy()
        if not dst.exists():
            src = Path(pol.path)
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            os.chmod(dst, 0o600)
        return dst
    return Path(pol.path)


def add(pol, grant: dict) -> tuple[Path, str]:
    """Append a grant to the active policy. Returns (path, message)."""
    path = target_policy(pol)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    grants = data.setdefault("grants", []) or []
    for g in grants:
        if g.get("tool") == grant["tool"] and g.get("match") == grant.get("match"):
            return path, "that grant is already in your policy"
    grants.append(grant)
    data["grants"] = grants
    tmp = path.with_suffix(path.suffix + ".tmp")
    header = _leading_comments(path)
    tmp.write_text(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                   encoding="utf-8")
    os.replace(tmp, path)
    return path, "granted"


def revoke(pol, index: int) -> tuple[Path, str]:
    path = target_policy(pol)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    grants = data.get("grants") or []
    if not 0 <= index < len(grants):
        return path, f"no grant #{index}"
    g = grants.pop(index)
    data["grants"] = grants
    header = _leading_comments(path)
    path.write_text(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                    encoding="utf-8")
    return path, f"revoked {g.get('tool')}"


def _leading_comments(path: Path) -> str:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            out.append(line)
        else:
            break
    return "\n".join(out).rstrip() + "\n\n" if out else ""
