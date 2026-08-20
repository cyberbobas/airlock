"""Product-surface tests: the things that decide whether a stranger can install
this, live with it for a week, and remove it cleanly.

These are not security tests. They are the difference between a working
prototype and something someone else can actually run.
"""
import json, os, pathlib, subprocess, sys, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite

from airlock import config, grants, install, report as reportmod, scan
from airlock.policy import ALLOW, ASK, BLOCK, Policy

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _env(home, ws):
    return dict(os.environ, AIRLOCK_HOME=str(home), AIRLOCK_WORKSPACE=str(ws),
                PYTHONPATH=str(ROOT), AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0")


def _cli(args, env):
    return subprocess.run([sys.executable, "-m", "airlock.cli", *args],
                          env=env, capture_output=True, text=True)


def main():
    s = Suite("PRODUCT SURFACE")

    # ---- 1. nothing that ships carries a personal path -------------------
    # Scans the whole package, not just the profiles: the first version of this
    # test only looked at YAML and happily shipped two docstrings pointing at
    # the author's home directory.
    pkg = pathlib.Path(config.PKG)
    offenders = []
    for f in list(pkg.rglob("*.py")) + list(pkg.rglob("*.yaml")) + list(pkg.rglob("*.json")):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if "/home/" in line or "/Users/" in line:
                offenders.append(f"{f.relative_to(pkg)}:{i}")
    s.check("nothing in the shipped package hardcodes a home directory",
            not offenders, offenders[:4])

    # ---- 2. profiles are real and differently postured -------------------
    modes = {}
    for prof in config.list_profiles():
        p = Policy.load(config.profile_path(prof))
        modes[prof] = p.mode
    s.check("three postures ship", set(config.list_profiles()) ==
            {"default", "paranoid", "yolo"}, config.list_profiles())
    s.check("yolo observes, default guards, paranoid enforces",
            modes == {"yolo": "observe", "default": "guard", "paranoid": "enforce"},
            modes)

    # ---- 3. ${workspace} makes a policy portable ------------------------
    ws = pathlib.Path(tempfile.mkdtemp(prefix="airlock-ws-"))
    os.environ["AIRLOCK_WORKSPACE"] = str(ws)
    p = Policy.load(config.profile_path("default"))
    s.check("${workspace} expands to this machine's workspace",
            p.decide("Read", {"file_path": f"{ws}/src/a.ts"}).action == ALLOW)
    s.check("a path outside the workspace is not auto-allowed",
            p.decide("Read", {"file_path": "/somewhere/else/a.ts"}).action != ALLOW)

    # ---- 4. grants: narrow, effective, and unable to lift a hard block ---
    # grant a directory OUTSIDE the workspace, so the workspace rule is not what
    # is being measured
    outside = pathlib.Path(tempfile.mkdtemp(prefix="airlock-out-"))
    p.grants = [{"tool": "Read", "match": f"{outside}/data/*", "reason": "t"}]
    s.check("a grant allows what it names",
            p.decide("Read", {"file_path": f"{outside}/data/x.csv"}).action == ALLOW)
    s.check("a grant does not leak to a sibling directory",
            p.decide("Read", {"file_path": f"{outside}/secrets/x.csv"}).action != ALLOW)
    p.grants = [{"tool": "Read", "match": "*", "reason": "t"}]
    s.check("even a wildcard grant cannot lift an absolute block",
            p.decide("Read", {"file_path": "/home/x/.ssh/id_rsa"}).action == BLOCK)
    p.grants = [{"tool": "Read", "match": "*", "reason": "t", "expires": "2000-01-01"}]
    s.check("an expired grant stops granting",
            p.decide("Read", {"file_path": "/somewhere/else/a.ts"}).action != ALLOW)

    # ---- 5. `allow` proposes the tightest thing that would have worked ---
    ev = {"tool": "Read", "resource": f"{ws}/data/a.csv",
          "_resources": [f"{ws}/data/a.csv", f"{ws}/data/b.csv", f"{ws}/data/c.csv"]}
    g = grants.propose(ev)
    s.check("allow folds repeated calls into one directory grant",
            g.get("match") == f"{ws}/data/*", g)

    # ---- 6. install / uninstall round trip -------------------------------
    fake = pathlib.Path(tempfile.mkdtemp(prefix="airlock-home-"))
    (fake / ".claude").mkdir()
    proj = fake / "proj"; proj.mkdir()
    settings = fake / ".claude" / "settings.json"
    mcp = proj / ".mcp.json"
    before_settings = {"model": "opus", "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "/my/own"}]}]}}
    before_mcp = {"mcpServers": {
        "time": {"command": "uvx", "args": ["mcp-server-time"]},
        "fs": {"command": "npx", "args": ["-y", "@x/fs"], "env": {"K": "1"}}}}
    # deliberately NOT formatted the way _save_json would write it — otherwise
    # "restored byte-for-byte" is only ever tested against our own serialiser
    settings_text = json.dumps(before_settings, separators=(",", ":"))
    mcp_text = ('{"mcpServers":{\n'
                '  "time": {"command":"uvx","args":["mcp-server-time"]},\n'
                '  "fs": {"command":"npx","args":["-y","@x/fs"],"env":{"K":"1"}}\n'
                '}}\n')
    before_mcp = json.loads(mcp_text)
    settings.write_text(settings_text)
    mcp.write_text(mcp_text)
    env = _env(fake / ".airlock", proj)
    env["CLAUDE_SETTINGS"] = str(settings)
    env["HOME"] = str(fake)

    r1 = _cli(["init", "--profile", "default"], env)
    s.check("init exits clean", r1.returncode == 0, r1.stderr[-300:])
    after = json.loads(mcp.read_text())
    s.check("init wraps every MCP server",
            all("_airlock_original" in v for v in after["mcpServers"].values()))
    s.check("init keeps the user's own hook",
            any("/my/own" in json.dumps(g) for g in
                json.loads(settings.read_text())["hooks"]["PreToolUse"]))
    s.check("init backs up what it edits",
            any(p.name.startswith("settings.json.airlock-bak")
                for p in (fake / ".claude").iterdir()))

    _cli(["init", "--profile", "default"], env)
    twice = json.loads(mcp.read_text())
    s.check("init is idempotent (no double wrapping)",
            all(v["args"].count("--server-id") == 1
                for v in twice["mcpServers"].values()),
            twice)

    r2 = _cli(["uninstall", "-y"], env)
    s.check("uninstall exits clean", r2.returncode == 0, r2.stderr[-300:])
    s.check("uninstall restores .mcp.json content",
            json.loads(mcp.read_text()) == before_mcp, mcp.read_text()[:200])
    s.check("uninstall restores .mcp.json byte-for-byte, formatting included",
            mcp.read_text() == mcp_text, repr(mcp.read_text()[:120]))
    s.check("uninstall restores settings.json byte-for-byte",
            settings.read_text() == settings_text, repr(settings.read_text()[:120]))
    s.check("uninstall keeps your data unless --purge",
            (fake / ".airlock" / "policy.yaml").exists())

    # ---- 7. the report exists and says something --------------------
    from airlock import audit
    os.environ["AIRLOCK_HOME"] = str(fake / ".airlock")
    for i in range(5):
        audit.record("decision", source="hook", tool="Read", decision="allow",
                     effective="allow", reason="in-workspace read")
    audit.record("decision", source="hook", tool="Bash", decision="block",
                 effective="block", reason="destructive recursive delete")
    rep = reportmod.build(days=7)
    s.check("report counts what happened", rep.total == 6, rep.total)
    s.check("report names what was refused",
            "destructive recursive delete" in dict(rep.blocked_reasons))
    s.check("report renders markdown for a human",
            "# Airlock report" in reportmod.render_markdown(rep))
    s.check("report checks the audit chain", rep.chain_ok)

    # ---- 8. SIEM export --------------------------------------------
    from airlock import export as exportmod
    cef = list(exportmod.export("cef"))
    s.check("CEF export produces CEF", cef and cef[0].startswith("CEF:0|Airlock|"),
            cef[:1])
    sl = list(exportmod.export("syslog"))
    s.check("syslog export is RFC5424-shaped",
            sl and sl[0].startswith("<") and "airlock@0" in sl[0], sl[:1])

    # ---- 9. the feed adds indicators, cannot remove built-ins --------
    from airlock import feed
    s.check("bundled feed loads", feed.load().get("version", 0) >= 1)
    s.check("feed adds detections beyond the built-ins",
            any(f["id"] == "secrets.token"
                for f in scan.scan_text("token ghp_ABCDEFGHIJKLMNOPQRSTUV")))
    bad = pathlib.Path(tempfile.mkstemp(suffix=".json")[1])
    bad.write_text(json.dumps({"version": 99, "patterns": [
        {"id": "x", "severity": "high", "regex": "([unclosed"}]}))
    ok, msg = feed.update(str(bad))
    s.check("a feed with a broken pattern is rejected", not ok, msg)
    s.check("built-in indicators survive a hostile feed",
            any(f["id"] == "secrets.ssh" for f in scan.scan_text("cat ~/.ssh/id_rsa")))

    # ---- 10. ask channel is honest about itself ----------------------
    from airlock import ask
    s.check("ask never silently defaults to a tty inside the proxy",
            "tty" not in ask.auto_backends())
    s.check("ask channel is describable", isinstance(ask.describe_channel(), str))

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
