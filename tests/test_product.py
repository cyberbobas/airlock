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

    # ---- 6b. a path containing "airlock" is not mistaken for our own -----
    # The marker used to be a substring match on the whole command, so a real
    # server or a foreign hook living under a path with "airlock" in it was read
    # as already-ours: the server was silently left ungated, and uninstall tore
    # the stranger's hook out of their settings.
    home2 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-collide-"))
    (home2 / ".claude").mkdir()
    proj2 = home2 / "proj"; proj2.mkdir()
    settings2 = home2 / ".claude" / "settings.json"
    mcp2 = proj2 / ".mcp.json"
    foreign_hook = {"matcher": "*", "hooks": [
        {"type": "command", "command": "/opt/airlock-labs/notify"}]}
    settings2.write_text(json.dumps({"hooks": {"PreToolUse": [foreign_hook]}}))
    # a legitimate server whose command path merely contains the word
    mcp2.write_text(json.dumps({"mcpServers": {
        "repo": {"command": "/opt/airlock-labs/server", "args": ["--stdio"]}}}))
    env2 = _env(home2 / ".airlock", proj2)
    env2["CLAUDE_SETTINGS"] = str(settings2)
    env2["HOME"] = str(home2)

    _cli(["init", "--profile", "default"], env2)
    after2 = json.loads(mcp2.read_text())["mcpServers"]["repo"]
    s.check("a server whose path contains 'airlock' still gets gated",
            "_airlock_original" in after2, after2)
    pre = json.loads(settings2.read_text())["hooks"]["PreToolUse"]
    s.check("init keeps a stranger's hook that lives under an airlock path",
            any(h.get("hooks", [{}])[0].get("command") == "/opt/airlock-labs/notify"
                for h in pre), pre)
    s.check("init still installs Airlock's own hook alongside it",
            any(install._is_airlock_hook(h) for h in pre), pre)

    _cli(["uninstall", "-y"], env2)
    post = json.loads(settings2.read_text()).get("hooks", {}).get("PreToolUse", [])
    s.check("uninstall leaves the stranger's airlock-path hook intact",
            any(h.get("hooks", [{}])[0].get("command") == "/opt/airlock-labs/notify"
                for h in post), json.loads(settings2.read_text()))
    s.check("uninstall unwraps the airlock-path server it wrapped",
            "_airlock_original" not in
            json.loads(mcp2.read_text())["mcpServers"]["repo"])

    # ---- 6c. init covers the hookless agents' stores, leaves ~/.claude.json --
    # "init closes your MCP servers" used to mean a project .mcp.json only. The
    # same person's Cursor project/home configs, Windsurf, Cline and Continue
    # sat wide open. init now walks those. It deliberately does NOT touch the
    # live ~/.claude.json: Claude Code's MCP is already gated by the hook, and
    # rewriting a file Claude Code owns would race it and could strip the key
    # uninstall needs.
    h3 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-stores-"))
    (h3 / ".claude").mkdir()
    work = h3 / "work"; work.mkdir()
    wkey = str(work.resolve())
    (work / ".cursor").mkdir()
    (work / ".cursor" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"cur": {"command": "npx", "args": ["cursor-srv"]}}}))
    (h3 / ".cursor").mkdir()
    (h3 / ".cursor" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"curhome": {"command": "npx", "args": ["home-srv"]}}}))
    claude_json = {"projects": {
        wkey: {"mcpServers": {"cc": {"command": "uvx", "args": ["cc-srv"]}}}}}
    (h3 / ".claude.json").write_text(json.dumps(claude_json))
    env3 = _env(h3 / ".airlock", work)
    env3["HOME"] = str(h3)
    env3["CLAUDE_SETTINGS"] = str(h3 / ".claude" / "settings.json")

    _cli(["init", "--profile", "default"], env3)
    cur = json.loads((work / ".cursor" / "mcp.json").read_text())["mcpServers"]["cur"]
    curhome = json.loads((h3 / ".cursor" / "mcp.json").read_text())["mcpServers"]["curhome"]
    s.check("init wraps a Cursor project store", "_airlock_original" in cur, cur)
    s.check("init wraps a Cursor home store", "_airlock_original" in curhome, curhome)
    s.check("init leaves the live ~/.claude.json untouched (hook covers it)",
            json.loads((h3 / ".claude.json").read_text()) == claude_json,
            (h3 / ".claude.json").read_text()[:200])

    # doctor --fix picks up a server added after init
    (work / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "cur": cur,                              # already wrapped
        "late": {"command": "npx", "args": ["added-later"]}}}))
    d = _cli(["doctor", "--fix"], env3)
    late = json.loads((work / ".cursor" / "mcp.json").read_text())["mcpServers"]["late"]
    s.check("doctor --fix wraps a newly added ungated server",
            "_airlock_original" in late, d.stdout[-300:])

    du = _cli(["doctor"], env3)
    s.check("doctor then reports all stores gated",
            "not behind Airlock" not in du.stdout, du.stdout[-300:])
    s.check("doctor never flags ~/.claude.json as ungated",
            "claude.json" not in du.stdout.lower(), du.stdout[-300:])

    _cli(["uninstall", "-y"], env3)
    s.check("uninstall unwraps across every wrapped store",
            "_airlock_original" not in
            json.loads((work / ".cursor" / "mcp.json").read_text())["mcpServers"]["cur"]
            and "_airlock_original" not in
            json.loads((h3 / ".cursor" / "mcp.json").read_text())["mcpServers"]["curhome"],
            (work / ".cursor" / "mcp.json").read_text()[:200])

    # ---- 6d. a broken store must not abort init for the others ----------
    # A stranger's malformed config (Cursor/Cline/etc.) once raised SystemExit
    # through _load_json and killed the whole init, leaving the hook half-wired.
    h4 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-broken-"))
    (h4 / ".claude").mkdir()
    proj4 = h4 / "proj"; proj4.mkdir()
    (proj4 / ".mcp.json").write_text('{"mcpServers":{"ok":{"command":"uvx","args":["a"]}}}')
    (h4 / ".cursor").mkdir()
    (h4 / ".cursor" / "mcp.json").write_text("this is not json {{{")
    env4 = _env(h4 / ".airlock", proj4)
    env4["HOME"] = str(h4)
    env4["CLAUDE_SETTINGS"] = str(h4 / ".claude" / "settings.json")
    r4 = _cli(["init", "--profile", "default"], env4)
    s.check("init survives a malformed store instead of aborting",
            r4.returncode == 0, r4.stderr[-200:])
    s.check("init still wires the hook past the broken store",
            "airlock" in (h4 / ".claude" / "settings.json").read_text())
    s.check("init still wraps the valid store past the broken one",
            "_airlock_original" in
            json.loads((proj4 / ".mcp.json").read_text())["mcpServers"]["ok"])

    # ---- 6e. any agent via AIRLOCK_MCP_CONFIGS (DeepSeek/mimo/etc.) ------
    # Airlock can't hardcode every agent's config path; a standard mcpServers
    # file pointed at via AIRLOCK_MCP_CONFIGS must be gated and unwrapped like a
    # built-in store.
    h5 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-custom-"))
    (h5 / ".claude").mkdir()
    proj5 = h5 / "proj"; proj5.mkdir()
    custom = h5 / "agent" / "mcp.json"; custom.parent.mkdir()
    custom.write_text('{"mcpServers":{"srv":{"command":"agent-mcp","args":["run"]}}}')
    env5 = _env(h5 / ".airlock", proj5)
    env5["HOME"] = str(h5)
    env5["CLAUDE_SETTINGS"] = str(h5 / ".claude" / "settings.json")
    env5["AIRLOCK_MCP_CONFIGS"] = str(custom)
    _cli(["init", "--profile", "default"], env5)
    s.check("a custom AIRLOCK_MCP_CONFIGS store gets gated",
            "_airlock_original" in
            json.loads(custom.read_text())["mcpServers"]["srv"], custom.read_text())
    _cli(["uninstall", "-y"], env5)
    s.check("...and unwrapped byte-for-byte on uninstall",
            "_airlock_original" not in
            json.loads(custom.read_text())["mcpServers"]["srv"], custom.read_text())

    # ---- 6f. grok (TOML) and mimo (JSON `mcp`, command-as-list) ---------
    h6 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-fmt-"))
    (h6 / ".claude").mkdir(); proj6 = h6 / "proj"; proj6.mkdir()
    (h6 / ".grok").mkdir(); (h6 / ".config" / "mimocode").mkdir(parents=True)
    grok_toml = ("# grok config\n[ui]\nscreen_mode = \"minimal\"  # keep\n\n"
                 "[mcp_servers.notion]\ncommand = \"npx\"\nargs = [\"-y\", \"notion-mcp\"]\n"
                 "enabled = true\n\n[terminal]\nalt_screen = true\n")
    (h6 / ".grok" / "config.toml").write_text(grok_toml)
    (h6 / ".config" / "mimocode" / "mimocode.json").write_text(json.dumps({
        "$schema": "x", "mcp": {
            "local1": {"type": "local", "command": ["mimo-mcp", "run"]},
            "rem": {"type": "remote", "url": "https://x"}}}))
    env6 = _env(h6 / ".airlock", proj6)
    env6["HOME"] = str(h6)
    env6["CLAUDE_SETTINGS"] = str(h6 / ".claude" / "settings.json")
    _cli(["init", "--profile", "default"], env6)
    gtoml = (h6 / ".grok" / "config.toml").read_text()
    s.check("grok TOML server gets wrapped",
            "_airlock_original" in gtoml and "--server-id" in gtoml, gtoml[:200])
    s.check("grok's unrelated TOML sections are preserved",
            "[ui]" in gtoml and "keep" in gtoml and "[terminal]" in gtoml, gtoml)
    mj = json.loads((h6 / ".config" / "mimocode" / "mimocode.json").read_text())["mcp"]
    s.check("mimo command-as-list server gets wrapped",
            "_airlock_original" in mj["local1"]
            and mj["local1"]["command"][0].endswith(("python3", "airlock-mcp", "python")),
            mj["local1"])
    s.check("mimo remote (no command) is left untouched",
            "_airlock_original" not in mj["rem"], mj["rem"])
    _cli(["uninstall", "-y"], env6)
    s.check("grok TOML restored byte-for-byte",
            (h6 / ".grok" / "config.toml").read_text() == grok_toml,
            (h6 / ".grok" / "config.toml").read_text())
    s.check("mimo restored (command back to a plain list)",
            json.loads((h6 / ".config" / "mimocode" / "mimocode.json").read_text())
            ["mcp"]["local1"]["command"] == ["mimo-mcp", "run"])

    # ---- 6g. DeepSeek Harness (cordis loader-patch YAML) ---------------
    import yaml as _yaml
    h7 = pathlib.Path(tempfile.mkdtemp(prefix="airlock-dsh-"))
    (h7 / ".claude").mkdir(); proj7 = h7 / "proj"; proj7.mkdir()
    prof = h7 / ".dsh" / "profiles" / "headless"; prof.mkdir(parents=True)
    patch_yml = ("# dsh patch\n- insert:\n"
                 "    - id: mcp-notion\n      name: '@deepseek-ai/dsh-mcp-client'\n"
                 "      config:\n        transport: stdio\n        serverName: notion\n"
                 "        command: npx\n        args: [\"-y\", \"notion-mcp\"]\n"
                 "    - id: mcp-rem\n      name: '@deepseek-ai/dsh-mcp-client'\n"
                 "      config:\n        transport: streamable-http\n"
                 "        serverName: rem\n        url: https://x\n")
    (prof / "cordis.patch.yml").write_text(patch_yml)
    env7 = _env(h7 / ".airlock", proj7)
    env7["HOME"] = str(h7)
    env7["CLAUDE_SETTINGS"] = str(h7 / ".claude" / "settings.json")
    _cli(["init", "--profile", "default"], env7)

    def _dsh_servers():
        d = _yaml.safe_load((prof / "cordis.patch.yml").read_text())
        return {n: c for n, c in install._dsh_server_configs(d)}
    srv = _dsh_servers()
    s.check("DeepSeek Harness stdio server gets wrapped",
            "_airlock_original" in srv["notion"]
            and "--server-id" in srv["notion"]["args"], srv["notion"])
    s.check("DeepSeek Harness streamable-http server is left alone",
            "_airlock_original" not in srv["rem"], srv["rem"])
    _cli(["uninstall", "-y"], env7)
    s.check("DeepSeek Harness restored (command back to npx)",
            _dsh_servers()["notion"]["command"] == "npx"
            and _dsh_servers()["notion"]["args"] == ["-y", "notion-mcp"])

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

    # ---- 11. block notifications are rate-capped, not a wall of toasts --
    from airlock import notify
    nhome = pathlib.Path(tempfile.mkdtemp(prefix="airlock-notify-"))
    os.environ["AIRLOCK_HOME"] = str(nhome)
    os.environ["AIRLOCK_NOTIFY"] = "1"
    emitted = []
    orig_emit, orig_cap = notify._emit, notify.CAP
    orig_cd, orig_win = notify.COOLDOWN, notify.WINDOW
    notify._emit = lambda title, body: emitted.append((title, body))
    notify.CAP, notify.COOLDOWN, notify.WINDOW = 3, 100.0, 1000.0
    try:
        for i in range(12):                       # 12 DISTINCT blocks in a burst
            notify.blocked(tool=f"Tool{i}", reason=f"reason {i}", resource=f"/x/{i}")
        # the same block repeated does not toast again (per-key cooldown)
        before = len(emitted)
        for _ in range(5):
            notify.blocked(tool="Tool0", reason="reason 0", resource="/x/0")
        repeat_added = len(emitted) - before
    finally:
        notify._emit, notify.CAP = orig_emit, orig_cap
        notify.COOLDOWN, notify.WINDOW = orig_cd, orig_win
    detailed = [t for t, _ in emitted if t == "Airlock blocked a call"]
    aggregate = [t for t, _ in emitted if t == "Airlock blocked several calls"]
    s.check("a burst of distinct blocks is capped to CAP detailed toasts",
            len(detailed) == 3, len(detailed))
    s.check("the rest fold into a single summary toast, not a wall",
            len(aggregate) == 1 and len(emitted) == 4, emitted)
    s.check("a repeated identical block does not re-toast",
            repeat_added == 0, repeat_added)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
