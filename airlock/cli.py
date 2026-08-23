"""airlock — one entry point for the whole tool.

  setup     init · uninstall · profile · policy · doctor
  daily     allow · check · log · monitor · report
  admission scan · pins · contracts · update
  evidence  verify · export
  runtime   mcp · hook · askd
  proof     bench · demo
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import subprocess
import sys
from pathlib import Path

from . import (__version__, audit, batch, bench as benchmod, config, contracts,
               export as exportmod, feed, grants, install, monitor as monitormod,
               pins, propose as proposemod, report as reportmod, scan)
from .policy import RANK, Policy

ROOT = Path(__file__).resolve().parents[1]
_C = {"h": "\033[31m", "m": "\033[33m", "l": "\033[32m", "b": "\033[1m",
      "d": "\033[2m", "c": "\033[36m", "0": "\033[0m"}


def _policy() -> Policy:
    return Policy.resolve()


def _say(rows, title=""):
    if title:
        print(f"\n  {_C['b']}{title}{_C['0']}")
    for kind, msg in rows:
        mark = {"ok": f"{_C['l']}✓{_C['0']}", "warn": f"{_C['m']}!{_C['0']}",
                "bad": f"{_C['h']}✗{_C['0']}", "-": " "}.get(kind, " ")
        print(f"  {mark} {msg}")


# ---- commands ----------------------------------------------------------
def cmd_scan(a) -> int:
    rep = batch.scan_path(a.path, min_severity=a.min_severity)
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(batch.render(rep, color=sys.stdout.isatty() and not a.no_color))
    if rep.errors and rep.files_scanned == 0:
        return 2
    return 1 if a.fail_on_findings and rep.counts()["high"] else 0


def cmd_check(a) -> int:
    """Dry-run a decision. The fastest way to answer 'would Airlock stop this?'"""
    try:
        args = json.loads(a.args_json) if a.args_json else {}
    except json.JSONDecodeError as e:
        print(f"airlock check: arguments must be JSON: {e}", file=sys.stderr)
        return 2
    pol = _policy()
    flags = scan.scan_text(json.dumps(args, ensure_ascii=False))
    raw = pol.apply_flags(pol.decide(a.tool, args), flags)
    kind, resource = contracts.classify(a.tool, args)

    server = a.tool.split("__")[1] if a.tool.startswith("mcp__") else None
    contract_line = ""
    if server:
        ct = contracts.get(server)
        if ct and ct.enforced:
            act, why = ct.check(a.tool.split("__")[-1], args)
            if RANK[act] > RANK[raw.action]:
                import dataclasses as _dc
                raw = _dc.replace(raw, action=act, reason=f"contract: {why}", rule=-1)
            contract_line = f"  contract   {act}{(' — ' + why) if why else ''}"

    # what the rules say, then what this mode actually does about it.
    # replace(), not mutation: posture() may hand back the same object, and
    # editing it in place would rewrite the rule verdict we are about to print.
    import dataclasses
    final = dataclasses.replace(pol.posture(raw))
    if final.action == "ask" and a.unattended:
        final = dataclasses.replace(
            final, action=pol.unattended_ask(),
            reason=final.reason + f" [no human -> {pol.unattended_ask()}]")

    tone = {"allow": _C["l"], "ask": _C["m"], "block": _C["h"]}
    print(f"\n  tool       {_C['c']}{a.tool}{_C['0']}")
    print(f"  resource   {kind}: {resource[:100]}")
    print(f"  rule       {tone[raw.action]}{raw.action.upper()}{_C['0']} — {raw.reason}")
    if contract_line:
        print(contract_line)
    if flags:
        print("  scan       " + ", ".join(
            f"{f['id']}({f['severity']})" for f in flags))
    print(f"  {_C['b']}effect     {tone[final.action]}{final.action.upper()}"
          f"{_C['0']} {_C['d']}(mode={pol.mode}){_C['0']}")
    print(f"  {_C['d']}policy={pol.path} ({pol.source}){_C['0']}\n")
    return {"allow": 0, "ask": 0, "block": 1}[final.action]


def cmd_pins(a) -> int:
    if a.action == "list":
        data = pins.load()
        if not data:
            print("  no pinned servers yet")
            return 0
        for sid, pin in sorted(data.items()):
            state = (f"{_C['h']}HELD{_C['0']}" if pin.get("held")
                     else f"{_C['l']}pinned{_C['0']}")
            print(f"\n  {_C['b']}{sid}{_C['0']}  [{state}]  "
                  f"{_C['d']}{pin.get('pinned_at','')}{_C['0']}")
            print(f"    hash   {pin.get('hash','')[:16]}…")
            print(f"    tools  {', '.join(pin.get('tools') or []) or '(none)'}")
            pend = pin.get("pending")
            if pend:
                added = sorted(set(pend.get("tools") or []) - set(pin.get("tools") or []))
                removed = sorted(set(pin.get("tools") or []) - set(pend.get("tools") or []))
                print(f"    {_C['h']}pending{_C['0']} {pend['hash'][:16]}… "
                      f"seen {pend.get('seen_at','')}")
                if added:
                    print(f"      + {', '.join(added)}")
                if removed:
                    print(f"      - {', '.join(removed)}")
                print(f"      {_C['d']}airlock pins approve {sid}{_C['0']}")
        print()
        return 0
    fn = {"approve": pins.approve, "reject": pins.reject, "forget": pins.forget}[a.action]
    msg = fn(a.server_id)
    audit.record(f"pin_{a.action}", source="cli", server=a.server_id,
                 effective="admit" if a.action == "approve" else "hold", reason=msg)
    print(f"  {msg}")
    return 0


def cmd_contracts(a) -> int:
    import yaml
    p = audit.home() / "contracts.yaml"
    if a.action == "list":
        data = yaml.safe_load(p.read_text()) if p.exists() else {}
        if not data:
            print("  no contracts yet")
            return 0
        for sid, c in sorted(data.items()):
            state = (f"{_C['l']}enforced{_C['0']}" if c.get("enforced")
                     else f"{_C['m']}proposal{_C['0']}")
            obs = " +observed" if c.get("_observed") else ""
            print(f"  {_C['b']}{sid:20}{_C['0']} [{state}]{obs}  "
                  f"tools={len(c.get('tools') or [])} fs={len(c.get('fs') or [])} "
                  f"net={len(c.get('net') or [])} shell={bool(c.get('shell'))}")
        print(f"\n  {_C['d']}{p}{_C['0']}")
        return 0
    if a.action == "show":
        data = yaml.safe_load(p.read_text()) if p.exists() else {}
        block = data.get(a.server_id)
        if not block:
            print(f"  no contract for '{a.server_id}'")
            return 1
        print(yaml.safe_dump({a.server_id: block}, sort_keys=True, allow_unicode=True))
        return 0
    msg = contracts.promote(a.server_id)
    audit.record("contract_promote", source="cli", server=a.server_id,
                 effective="admit", reason=msg)
    print(f"  {msg}")
    return 0


def cmd_log(a) -> int:
    p = audit.audit_path()
    if a.follow:
        os.execvp("tail", ["tail", "-f", str(p)])
    if not p.exists():
        print("  no audit log yet")
        return 0
    lines = p.read_text(encoding="utf-8").splitlines()[-a.n:]
    if a.json:
        for l in lines:
            print(l)
        return 0
    tone = {"allow": _C["l"], "ask": _C["m"], "block": _C["h"], "hold": _C["h"],
            "flag": _C["c"], "admit": _C["c"]}
    for l in lines:
        try:
            r = json.loads(l)
        except Exception:
            continue
        eff = audit.safe(r.get("effective") or r.get("decision") or r.get("event"))
        who = audit.safe(r.get("tool") or r.get("server") or "-", 34)
        res = audit.safe(r.get("resource") or r.get("detail") or "", 40)
        print(f"  {_C['d']}{audit.safe(r.get('ts',''), 19)}{_C['0']} "
              f"{tone.get(eff,'')}{eff.upper():6}{_C['0']} "
              f"{_C['d']}{audit.safe(r.get('source',''), 4):4}{_C['0']} {who:34} "
              f"{audit.safe(r.get('reason',''), 60):60} {_C['d']}{res}{_C['0']}")
    return 0


def cmd_verify(a) -> int:
    """Exit 0 fully verified, 1 chain broken, 2 verified but incomplete.

    The third state is real and worth its own code: a log whose tail checkpoint
    is missing verifies as far as it goes, but nothing proves records were not
    removed from the end — and a cron job checking only for zero would call that
    a pass.
    """
    ok, n, msg = audit.verify(all_segments=True)
    incomplete = ok and "no tail checkpoint" in msg
    if not ok:
        label, tone = "CHAIN BROKEN", _C["h"]
    elif incomplete:
        label, tone = "CHAIN INCOMPLETE", _C["m"]
    else:
        label, tone = "CHAIN INTACT", _C["l"]
    print(f"\n  {tone}{label}{_C['0']}  {msg.split(' (no tail')[0]}")
    if incomplete:
        print(f"  {_C['m']}!{_C['0']} audit.head is missing — records removed from "
              f"the end of the log would not be detected.")
    print(f"  {_C['d']}{audit.audit_path()}{_C['0']}\n")
    return 0 if ok and not incomplete else (2 if incomplete else 1)


def cmd_doctor(a) -> int:
    """Tell the operator what is actually enforcing, not what is installed."""
    if getattr(a, "fix", False):
        fixres = install.fix(project=config.workspace())
        if fixres.changes:
            print(f"\n  {_C['b']}FIXED{_C['0']}")
            for c in fixres.changes:
                print(f"  {_C['l']}✓{_C['0']} {c.what}  {_C['d']}{c.path}{_C['0']}")
        else:
            print(f"\n  {_C['d']}doctor --fix: nothing to wire — already covered"
                  f"{_C['0']}")
        for n in fixres.notes:
            print(f"  {_C['d']}· {n}{_C['0']}")
    rows = []
    pol_path, why, proj = config.resolve_policy_chain()
    try:
        pol = Policy.resolve()
        rows.append(("ok", f"policy: {pol_path} ({why})"))
        rows.append(("ok", f"policy loads: {len(pol.rules)} rules, mode={pol.mode}"))
        if proj:
            over = pol.overlay
            rows.append(("ok", f"project overlay: {proj} — "
                               f"{len(over.rules) if over else 0} rules, tighten-only "
                               f"(a repository cannot loosen your policy)"))
        if not pol.has_teeth() and pol.mode != "observe":
            rows.append(("bad", "this policy has no block rules — nothing is being "
                                "enforced (airlock profile default --force)"))
        if pol.mode == "observe":
            rows.append(("warn", "mode=observe — nothing is being blocked (learn phase). "
                                 "Promote to guard once you have a baseline."))
        elif pol.mode == "guard":
            rows.append(("ok", "mode=guard — explicit block rules enforced, "
                               "unmatched calls allowed and logged"))
        if not pol.escalate:
            rows.append(("warn", "no `escalate:` — scan flags cannot tighten a decision"))
    except Exception as e:
        rows.append(("bad", f"policy {pol_path} does not load: {e}"))
        pol = None
    ws = config.workspace()
    try:
        at_home = ws == pathlib.Path.home().resolve()
    except (OSError, RuntimeError):
        at_home = False
    if at_home:
        rows.append(("warn", f"workspace: {ws} — that is your home directory, so "
                             f"every `${{workspace}}` rule covers all of it. Run the "
                             f"agent from the project, or set AIRLOCK_WORKSPACE."))
    else:
        rows.append(("ok", f"workspace: {ws}"))

    h = audit.home()
    rows.append(("ok", f"airlock home: {h}"))
    ok, n, msg = audit.verify()
    rows.append(("ok" if ok else "bad", f"audit: {msg}"))

    held = [s for s, p in pins.load().items() if p.get("held")]
    if held:
        rows.append(("warn", f"held servers (calls blocked): {', '.join(held)}"))

    import yaml
    cp = h / "contracts.yaml"
    data = yaml.safe_load(cp.read_text()) if cp.exists() else {}
    enforced = [k for k, v in (data or {}).items() if v.get("enforced")]
    proposals = [k for k, v in (data or {}).items() if not v.get("enforced")]
    if enforced:
        rows.append(("ok", f"enforced contracts: {', '.join(enforced)}"))
    if proposals:
        rows.append(("warn", f"contract proposals not yet enforced: {', '.join(proposals)}"
                             f"  (airlock contracts promote <id>)"))

    from . import ask as askmod, notify
    chan = askmod.describe_channel()
    if chan == "none (ask resolves unattended)":
        lands = pol.unattended_ask() if pol else "block"
        rows.append(("warn", f"no way to ask you — every `ask` resolves to "
                             f"{lands.upper()} (run: airlock askd)"))
    else:
        rows.append(("ok", f"ask reaches you via: {chan}"))
    rows.append(("ok", f"block notifications: {notify._backend() or 'none available'}")
                if notify.enabled() and notify._backend() else
                ("warn", "no desktop notifier — a block will be silent "
                         "(install notify-send / terminal-notifier)"))
    rows.append(("ok", feed.status()))

    settings = install.claude_settings()
    wired = False
    if settings.exists():
        try:
            groups = (json.loads(settings.read_text()).get("hooks")
                      or {}).get("PreToolUse") or []
            wired = any(install._is_airlock_hook(g) for g in groups)
        except Exception:
            wired = False
    rows.append(("ok", "Claude Code PreToolUse hook is wired") if wired else
                ("warn", f"hook not in {settings} — native tools are ungated "
                         f"(run: airlock init)"))
    stores = install.mcp_stores(ws)
    ungated, gated = [], 0
    for label, mp in stores:
        try:
            data = json.loads(mp.read_text())
        except Exception:
            continue
        for servers in install._server_maps(data):
            for name, spec in servers.items():
                if not isinstance(spec, dict) or not spec.get("command"):
                    continue
                if install._is_wrapped(spec):
                    gated += 1
                else:
                    ungated.append(f"{name} [{label}]")
    if ungated:
        more = f" (+{len(ungated) - 6} more)" if len(ungated) > 6 else ""
        rows.append(("warn", f"MCP servers not behind Airlock: "
                             f"{', '.join(ungated[:6])}{more}"
                             f" — run: airlock doctor --fix"))
    elif gated:
        rows.append(("ok", f"all {gated} MCP server(s) across {len(stores)} "
                           f"store(s) are gated"))
    elif stores:
        rows.append(("ok", f"{len(stores)} MCP store(s) present, no servers "
                           f"defined yet"))

    if not sys.stdout.isatty():
        for k, m in rows:
            print(f"{k.upper():4} {m}")
    else:
        mark = {"ok": f"{_C['l']}✓{_C['0']}", "warn": f"{_C['m']}!{_C['0']}",
                "bad": f"{_C['h']}✗{_C['0']}"}
        print(f"\n  {_C['b']}AIRLOCK DOCTOR{_C['0']}\n")
        for k, m in rows:
            print(f"  {mark[k]} {m}")
        print()
    return 1 if any(k == "bad" for k, _ in rows) else 0


def cmd_init(a) -> int:
    res = install.init(a.profile, hook=not a.no_hook, mcp=not a.no_mcp,
                       force=a.force)
    print(f"\n  {_C['b']}Airlock installed{_C['0']}  {_C['d']}profile: {a.profile}{_C['0']}")
    for c in res.changes:
        print(f"  {_C['l']}✓{_C['0']} {c.what}")
        print(f"    {_C['d']}{c.path}" + (f"  (backup: {c.backup})" if c.backup else "")
              + _C['0'])
    for n in res.notes:
        print(f"  {_C['d']}· {n}{_C['0']}")
    print(f"\n  {_C['d']}Next: restart your agent, then `airlock doctor`. "
          f"Undo anytime with `airlock uninstall`.{_C['0']}\n")
    audit.record("install", source="cli", effective="admit",
                 reason=f"init --profile {a.profile}",
                 extra="; ".join(c.what for c in res.changes))
    return 0


def _confirm(prompt: str, *, default_no: bool = True) -> bool:
    """Ask, or refuse to guess.

    A bare input() raises EOFError under CI, a pipe, or a hook — and the place
    that happened was `uninstall`, i.e. someone removing the product gets a
    Python traceback on their way out. Non-interactive callers must pass -y.
    """
    if not sys.stdin.isatty():
        print(f"  {_C['m']}!{_C['0']} not running interactively — re-run with "
              f"{_C['b']}-y{_C['0']} to confirm", file=sys.stderr)
        return False
    try:
        ans = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in (("y", "yes") if default_no else ("", "y", "yes"))


def cmd_uninstall(a) -> int:
    if not a.yes:
        print(f"\n  This will unwire the Claude Code hook and unwrap your MCP "
              f"servers.")
        if a.purge:
            print(f"  {_C['h']}--purge also deletes {config.home()} "
                  f"(policy, pins, contracts, audit log).{_C['0']}")
        if not _confirm("  Proceed? [y/N] "):
            print("  cancelled\n")
            return 1
    res = install.uninstall(purge=a.purge)
    print()
    for c in res.changes:
        print(f"  {_C['l']}✓{_C['0']} {c.what}  {_C['d']}{c.path}{_C['0']}")
    for n in res.notes:
        print(f"  {_C['d']}· {n}{_C['0']}")
    if not res.changes:
        print(f"  {_C['d']}nothing was wired up{_C['0']}")
    print()
    return 0


def cmd_profile(a) -> int:
    if not a.name:
        cur = _policy()
        print(f"\n  active: {_C['b']}{cur.profile or '(custom)'}{_C['0']} "
              f"{_C['d']}via {cur.source} — {cur.path}{_C['0']}")
        print(f"  available: {', '.join(config.list_profiles())}\n")
        return 0
    res = install.Result()
    install.install_policy(a.name, res, force=a.force)
    for c in res.changes:
        print(f"  {_C['l']}✓{_C['0']} {c.what}  {_C['d']}{c.path}{_C['0']}")
    for n in res.notes:
        print(f"  {_C['d']}· {n}{_C['0']}")
    return 0


def cmd_demo(a) -> int:
    from . import demo
    return demo.run(color=not a.no_color)


def cmd_monitor(a) -> int:
    return monitormod.run(interval=a.interval, once=a.once)


def cmd_propose(a) -> int:
    """Derive the narrowest policy that still covers what agents already did."""
    prop = proposemod.build(days=a.days, min_count=a.min_count)
    if not prop.allowed and not prop.grants:
        print("  no allowed calls in the audit log yet — run in yolo/observe "
              "for a while, then propose")
        return 1
    tools = len({g["tool"] for g in prop.grants})
    print(f"\n  {_C['b']}POLICY PROPOSAL{_C['0']}  {_C['d']}from {prop.allowed} "
          f"allowed call(s) over {a.days}d{_C['0']}")
    print(f"  {_C['l']}{len(prop.grants)}{_C['0']} least-privilege grant(s) across "
          f"{tools} tool(s)")
    if prop.risky:
        print(f"  {_C['h']}{sum(prop.risky.values())}{_C['0']} high-flag call(s) "
              f"NOT whitelisted — review: {', '.join(list(prop.risky)[:5])}")
    if prop.gated:
        print(f"  {_C['m']}{sum(prop.gated.values())}{_C['0']} already-gated "
              f"call(s) left as they are")
    if prop.unscopable:
        print(f"  {_C['d']}{sum(prop.unscopable.values())} allowed call(s) had no "
              f"path/host to scope — not proposed{_C['0']}")
    if prop.truncated:
        print(f"  {_C['d']}{prop.truncated} extra match(es) dropped by the "
              f"per-tool cap{_C['0']}")
    print()
    if a.apply:
        pol = _policy()
        added, skipped = proposemod.apply(pol, prop)
        print(f"  {_C['l']}✓{_C['0']} applied {added} grant(s) to {pol.path}"
              + (f" ({skipped} already present)" if skipped else ""))
        print(f"  {_C['d']}now make them bite: airlock profile default{_C['0']}\n")
    else:
        print(proposemod.to_yaml(prop))
        print(f"  {_C['d']}review, then: airlock policy propose --apply{_C['0']}\n")
    return 0


def cmd_allow(a) -> int:
    pol = _policy()
    if a.target == "last":
        ev = grants.last_gated()
        if not ev:
            print("  nothing has been blocked or asked about yet")
            return 1
        # fold in every other time the same thing was gated, so one grant covers
        # the whole recurring annoyance instead of only its latest instance
        for g in grants.recent_gated(20):
            if g.get("tool") == ev.get("tool"):
                ev = g
                break
        events = [ev]
    elif a.target == "list":
        gs = pol.grants or []
        if not gs:
            print(f"\n  no grants yet  {_C['d']}({pol.path}){_C['0']}\n")
            return 0
        print(f"\n  {_C['b']}Grants{_C['0']} {_C['d']}{pol.path}{_C['0']}")
        for i, g in enumerate(gs):
            exp = f"  expires {g['expires']}" if g.get("expires") else ""
            print(f"  {_C['d']}[{i}]{_C['0']} {_C['c']}{g.get('tool')}{_C['0']}"
                  f"{('  ' + g['match']) if g.get('match') else ''}"
                  f"  {_C['d']}{g.get('reason','')}{exp}{_C['0']}")
        print(f"\n  {_C['d']}revoke: airlock allow revoke <n>{_C['0']}\n")
        return 0
    elif a.target == "revoke":
        if a.tool is None:
            print("  usage: airlock allow revoke <n>", file=sys.stderr)
            return 2
        try:
            index = int(a.tool)
        except ValueError:
            print(f"  usage: airlock allow revoke <n> — {a.tool!r} is not a number",
                  file=sys.stderr)
            return 2
        path, msg, changed = grants.revoke(pol, index)
        print(f"  {msg}  {_C['d']}{path}{_C['0']}")
        return 0 if changed else 1
    elif a.target == "recent":
        rec = grants.recent_gated(a.n)
        if not rec:
            print("  nothing has been blocked or asked about yet")
            return 0
        print(f"\n  {_C['b']}What Airlock got in the way of{_C['0']}  "
              f"{_C['d']}most frequent first{_C['0']}")
        for e in rec:
            eff = e.get("effective", "?")
            tone = _C["h"] if eff == "block" else _C["m"]
            times = f"{e['_count']}×" if e.get("_count", 1) > 1 else " ·"
            print(f"  {_C['b']}{times:>5}{_C['0']} {tone}{eff.upper():5}{_C['0']} "
                  f"{_C['c']}{e.get('tool')}{_C['0']}  {_C['d']}{e.get('reason','')[:50]}{_C['0']}")
            for r in (e.get("_resources") or [])[:3]:
                print(f"          {_C['d']}{r}{_C['0']}")
        print(f"\n  {_C['d']}allow the top one: airlock allow last{_C['0']}\n")
        return 0
    else:
        tool = (f"mcp__{a.target}__{a.tool}" if a.tool else a.target)
        events = [{"tool": tool, "resource": a.match or "", "reason": "manual"}]

    ok = 0
    for ev in events:
        g = grants.propose(ev)
        if not g:
            print("  could not work out what to grant")
            return 1
        if a.match:
            g["match"] = a.match
        if a.expires:
            g["expires"] = a.expires
        hard = grants.hard_blocked(
            pol, g, ev.get("_resources") or ([ev.get("resource")] if ev.get("resource") else []))
        if hard:
            print(f"\n  {_C['h']}refused{_C['0']}: an absolute block rule still "
                  f"applies — {hard}")
            print(f"  {_C['d']}Grants cannot lift hard blocks. Edit "
                  f"{pol.path} deliberately if you really mean it.{_C['0']}\n")
            return 1
        print(f"\n  {_C['b']}Grant to add{_C['0']}")
        print(f"    tool   {_C['c']}{g['tool']}{_C['0']}")
        if g.get("match"):
            print(f"    match  {g['match']}")
        if g.get("expires"):
            print(f"    expires {g['expires']}")
        print(f"    {_C['d']}{g['reason']}{_C['0']}")
        if not a.yes and sys.stdin.isatty():
            if not _confirm("\n  Add it? [Y/n] ", default_no=False):
                print("  cancelled\n")
                return 1
        path, msg = grants.add(pol, g)
        audit.record("grant", source="cli", tool=g["tool"], effective="admit",
                     reason=msg, extra=g.get("match", ""))
        print(f"  {_C['l']}✓{_C['0']} {msg}  {_C['d']}{path}{_C['0']}")
        ok += 1
    print(f"\n  {_C['d']}Takes effect on the next call — no restart needed.{_C['0']}\n")
    return 0 if ok else 1


def cmd_report(a) -> int:
    r = reportmod.build(days=a.days)
    if a.json:
        print(json.dumps(r.to_dict(), indent=2, ensure_ascii=False))
    elif a.markdown:
        print(reportmod.render_markdown(r))
    else:
        print(reportmod.render(r, color=sys.stdout.isatty() and not a.no_color))
    return 0


def cmd_bench(a) -> int:
    r = benchmod.run(a.decisions, a.calls)
    print(json.dumps(r, indent=2) if a.json else benchmod.render(r))
    return 0


def cmd_export(a) -> int:
    for line in exportmod.export(a.format, days=a.days):
        print(line)
    return 0


def cmd_update(a) -> int:
    if a.status:
        print(f"  {feed.status()}")
        return 0
    ok, msg = feed.update(a.url, allow_unsigned=a.allow_unsigned)
    print(f"  {_C['l'] if ok else _C['h']}{'✓' if ok else '✗'}{_C['0']} {msg}")
    audit.record("feed_update", source="cli", effective="admit" if ok else "block",
                 reason=msg)
    return 0 if ok else 1


_PASSTHROUGH = {"mcp": "airlock.mcp_proxy", "hook": "airlock.cc_hook",
                "askd": "airlock.askd"}


def _exec_module(mod: str, argv: list[str]) -> int:
    env = dict(os.environ, PYTHONPATH=f"{ROOT}{os.pathsep}" + os.environ.get("PYTHONPATH", ""))
    return subprocess.call([sys.executable, "-m", mod, *argv], env=env)


# ---- parser ------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="airlock",
                                description="Runtime firewall for AI coding agents.")
    p.add_argument("--version", action="version",
                   version=f"airlock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="static admission scan of a skill/MCP folder")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--min-severity", choices=("high", "med", "low"), default="low")
    s.add_argument("--fail-on-findings", action="store_true",
                   help="exit 1 if any high-severity flag was found (for CI)")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("check", help="dry-run one tool call against the policy")
    s.add_argument("tool")
    s.add_argument("args_json", nargs="?", default="{}")
    s.add_argument("--unattended", action="store_true",
                   help="resolve `ask` as it would resolve with no human present")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("pins", help="toolset pins (plane 4 admission)")
    s.add_argument("action", nargs="?", default="list",
                   choices=("list", "approve", "reject", "forget"))
    s.add_argument("server_id", nargs="?")
    s.set_defaults(fn=cmd_pins)

    s = sub.add_parser("contracts", help="per-skill least-privilege contracts")
    s.add_argument("action", nargs="?", default="list",
                   choices=("list", "show", "promote"))
    s.add_argument("server_id", nargs="?")
    s.set_defaults(fn=cmd_contracts)

    s = sub.add_parser("log", help="recent decisions")
    s.add_argument("-n", type=int, default=25)
    s.add_argument("-f", "--follow", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_log)

    s = sub.add_parser("init", help="wire Airlock into this machine")
    s.add_argument("--profile", default=config.DEFAULT_PROFILE,
                   choices=config.list_profiles())
    s.add_argument("--no-hook", action="store_true", help="skip the Claude Code hook")
    s.add_argument("--no-mcp", action="store_true", help="skip wrapping MCP servers")
    s.add_argument("--force", action="store_true", help="overwrite an existing policy")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("uninstall", help="remove every change Airlock made")
    s.add_argument("--purge", action="store_true",
                   help="also delete $AIRLOCK_HOME (policy, pins, audit log)")
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(fn=cmd_uninstall)

    s = sub.add_parser("profile", help="show or switch the policy profile")
    s.add_argument("name", nargs="?", choices=config.list_profiles())
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_profile)

    s = sub.add_parser("policy", help="work with the active policy")
    psub = s.add_subparsers(dest="paction", required=True)
    pp = psub.add_parser("propose",
                         help="derive least-privilege grants from the audit log")
    pp.add_argument("--days", type=int, default=30,
                    help="how far back to read the audit log")
    pp.add_argument("--min-count", type=int, default=1, dest="min_count",
                    help="only propose for tools seen at least this many times")
    pp.add_argument("--apply", action="store_true",
                    help="write the proposed grants into your policy")
    pp.set_defaults(fn=cmd_propose)

    s = sub.add_parser("allow", help="permit what was just blocked")
    s.add_argument("target", nargs="?", default="last",
                   help="'last', 'recent', 'list', 'revoke', or a server id")
    s.add_argument("tool", nargs="?", help="tool name, or grant index for revoke")
    s.add_argument("--match", help="narrow the grant to this path/host glob")
    s.add_argument("--expires", help="YYYY-MM-DD; the grant stops working after this")
    s.add_argument("-n", type=int, default=10, help="how many for 'recent'")
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(fn=cmd_allow)

    s = sub.add_parser("report", help="what Airlock did over a period")
    s.add_argument("--days", type=int, default=7)
    s.add_argument("--json", action="store_true")
    s.add_argument("--markdown", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("bench", help="measured overhead per call")
    s.add_argument("--decisions", type=int, default=2000)
    s.add_argument("--calls", type=int, default=300)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("export", help="audit records for a SIEM")
    s.add_argument("--format", choices=exportmod.FORMATS, default="cef")
    s.add_argument("--days", type=float, default=0, help="0 = everything")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("update", help="refresh the threat-indicator feed")
    s.add_argument("url", nargs="?", help="feed URL or file (default: the public feed)")
    s.add_argument("--status", action="store_true")
    s.add_argument("--allow-unsigned", action="store_true",
                   help="install a feed that carries no verifiable signature")
    s.set_defaults(fn=cmd_update)

    s = sub.add_parser("monitor", help="live screen of decisions as they happen")
    s.add_argument("--interval", type=float, default=0.5,
                   help="seconds between refreshes")
    s.add_argument("--once", action="store_true",
                   help="render a single snapshot and exit (no live loop)")
    s.set_defaults(fn=cmd_monitor)

    s = sub.add_parser("demo", help="watch a key-theft get refused (self-contained)")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(fn=cmd_demo)

    sub.add_parser("verify", help="check the audit hash chain").set_defaults(fn=cmd_verify)
    s = sub.add_parser("doctor", help="what is actually enforcing?")
    s.add_argument("--fix", action="store_true",
                   help="wrap any ungated MCP servers and wire a missing hook")
    s.set_defaults(fn=cmd_doctor)

    for name, mod in (("mcp", "airlock.mcp_proxy"), ("hook", "airlock.cc_hook"),
                      ("askd", "airlock.askd")):
        s = sub.add_parser(name, help=f"run {mod}")
        s.add_argument("rest", nargs=argparse.REMAINDER)
        s.set_defaults(fn=lambda a, _m=mod: _exec_module(_m, a.rest))
    return p


def main(argv=None) -> int:
    # `airlock hook --post` and `airlock mcp -- server args` hand options
    # through to the module they run. argparse rejects an unknown option
    # before REMAINDER ever sees it, so the passthrough commands are split off
    # before parsing: `init` writes `airlock hook --post` whenever the
    # console script is not on PATH, and that form exited 2 on every single
    # tool call instead of recording an outcome.
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _PASSTHROUGH:
        return _exec_module(_PASSTHROUGH[argv[0]], argv[1:])
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", "") in ("pins", "contracts") and \
            args.action not in ("list",) and not args.server_id:
        print(f"airlock {args.cmd} {args.action}: needs a server id", file=sys.stderr)
        return 2
    try:
        return args.fn(args) or 0
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
