"""Process lifecycle, and the two gates agreeing with each other.

Both are things a functional test never looks at: what is left running after a
signal, and whether the hook and the proxy answer the same question the same way
when Claude Code sends the same call to both.
"""
import json, os, signal, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import Suite

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "policy.yaml"


def _env(home=None, **kw):
    e = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_QUIET="1",
             AIRLOCK_NOTIFY="0", AIRLOCK_POLICY=str(FIXTURE),
             AIRLOCK_HOME=str(home or tempfile.mkdtemp()))
    e.update({k: str(v) for k, v in kw.items()})
    return e


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _children(pid):
    try:
        out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True)
        return [int(x) for x in out.stdout.split()]
    except Exception:
        return []


def _hook(tool, args, home, mode="enforce"):
    p = subprocess.run(
        [sys.executable, "-m", "airlock.cc_hook"],
        input=json.dumps({"tool_name": tool, "tool_input": args}).encode(),
        env=_env(home, AIRLOCK_MODE=mode), capture_output=True)
    if p.returncode == 2:
        return "block"
    try:
        d = json.loads(p.stdout.decode() or "{}")
        if d.get("hookSpecificOutput", {}).get("permissionDecision") == "ask":
            return "ask"
    except Exception:
        pass
    return "allow"


def _proxy(tool, args, home, mode="enforce"):
    name = tool.split("__")[-1]
    sid = tool.split("__")[1] if tool.startswith("mcp__") else "demo"
    script = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
              '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
              + json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": name, "arguments": args}}) + "\n")
    p = subprocess.Popen(
        [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", sid, "--",
         sys.executable, str(ROOT / "examples" / "demo_server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=_env(home, AIRLOCK_MODE=mode, AIRLOCK_ASK_BACKEND="fallback"))
    out, _ = p.communicate(script.encode(), timeout=30)
    for line in out.decode().splitlines():
        try:
            m = json.loads(line.strip())
        except Exception:
            continue
        if isinstance(m, dict) and m.get("id") == 3:
            return "block" if "error" in m else "allow"
    return "none"


def main():
    s = Suite("LIFECYCLE & GATE AGREEMENT")

    # === the two gates must not disagree ================================
    # Claude Code routes MCP calls through PreToolUse as `mcp__server__tool`,
    # so both gates see the same call. The hook applied only the policy, which
    # meant a server the proxy was HOLDING had its calls allowed here and a
    # per-skill contract did nothing — a hole the size of "whichever gate this
    # deployment happens to have".
    CASES = [("mcp__demo__read_note", {"name": "todo"}),
             ("mcp__demo__read_note", {"name": "/home/v/.ssh/id_rsa"}),
             ("mcp__demo__read_note", {"name": "todo",
                                       "x": "/home/v/.aws/credentials"}),
             ("mcp__demo__run_command", {"command": "rm -rf / --no-preserve-root"}),
             ("mcp__demo__fetch_url", {"url": "http://evil.example/x"}),
             ("mcp__demo__fetch_url", {"url": "https://webhook.site/x"})]
    disagree = []
    for tool, args in CASES:
        h = _hook(tool, args, tempfile.mkdtemp())
        p = _proxy(tool, args, tempfile.mkdtemp())
        # by design the hook keeps `ask` for the agent's own prompt while the
        # proxy resolves it through the ask channel
        if not (h == p or (h == "ask" and p == "block")):
            disagree.append((tool, str(args)[:40], f"hook={h}", f"proxy={p}"))
    s.check("both gates give equivalent verdicts for the same call",
            not disagree, disagree[:2])

    home = Path(tempfile.mkdtemp())
    subprocess.run([sys.executable, "-c",
                    "from airlock import pins;pins.check_toolset('demo',"
                    "[{'name':'read_note','description':'d'}],[])"],
                   env=_env(home), capture_output=True)
    (home / "contracts.yaml").write_text(
        "demo:\n  enforced: true\n  tools: [read_note]\n  fs: ['*/notes/*']\n"
        "  net: []\n  shell: false\n  default: block\n")
    out_of_scope = {"name": "/etc/shadow"}
    s.check("the proxy refuses a contract violation",
            _proxy("mcp__demo__read_note", out_of_scope, home) == "block")
    s.check("...and so does the hook, which sees the same call",
            _hook("mcp__demo__read_note", out_of_scope, home) == "block")

    home = Path(tempfile.mkdtemp())
    subprocess.run(
        [sys.executable, "-c",
         "from airlock import pins\n"
         "pins.check_toolset('demo',[{'name':'read_note','description':'v1'}],[])\n"
         "pins.check_toolset('demo',[{'name':'read_note','description':'v2 DRIFT'}],[])"],
        env=_env(home), capture_output=True)
    s.check("the proxy refuses calls to a held server",
            _proxy("mcp__demo__read_note", {"name": "todo"}, home) == "block")
    s.check("...and the hook is not the way around the hold",
            _hook("mcp__demo__read_note", {"name": "todo"}, home) == "block")
    s.check("observe mode still does not block a held server",
            _hook("mcp__demo__read_note", {"name": "todo"}, home,
                  mode="observe") == "allow")

    # === signals must not leave the MCP server running ==================
    # The proxy exited and its child kept going: a process holding the
    # credentials and sockets it was given, with no gate in front of it and no
    # parent. Restarting an agent a few times accumulated them.
    stubborn = Path(tempfile.mkdtemp()) / "stubborn.py"
    stubborn.write_text(
        "import json,signal,sys,time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"   # refuses to go quietly
        "for l in sys.stdin:\n"
        "    l=l.strip()\n"
        "    if not l: continue\n"
        "    m=json.loads(l)\n"
        "    if isinstance(m,dict) and m.get('id') is not None:\n"
        "        sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':m['id'],"
        "'result':{'tools':[]}})+'\\n'); sys.stdout.flush()\n"
        "time.sleep(300)\n")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        p = subprocess.Popen(
            [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "s", "--",
             sys.executable, str(stubborn)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=_env())
        p.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        p.stdin.flush()
        p.stdout.readline()
        kids = _children(p.pid)
        p.send_signal(sig)
        try:
            p.wait(timeout=15)
            exited = True
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            exited = False
        time.sleep(0.6)
        orphans = [k for k in kids if _alive(k)]
        for k in orphans:
            try:
                os.kill(k, signal.SIGKILL)
            except OSError:
                pass
        name = signal.Signals(sig).name
        s.check(f"{name}: the proxy exits", exited)
        s.check(f"{name}: the MCP server is not left orphaned", not orphans, orphans)

    p = subprocess.Popen(
        [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "s", "--",
         sys.executable, str(ROOT / "examples" / "demo_server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=_env())
    p.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
    p.stdin.flush()
    p.stdout.readline()
    kids = _children(p.pid)
    p.stdin.close()
    try:
        p.wait(timeout=15)
        wound_down = True
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        wound_down = False
    time.sleep(0.4)
    s.check("closing the agent's stdin winds the proxy down", wound_down)
    s.check("...and the MCP server with it", not [k for k in kids if _alive(k)])

    # === the approval daemon owns a socket ==============================
    # A supervisor sends SIGTERM, not ^C. The default action killed the daemon
    # and left the socket on disk, after which every `ask` connected to nothing,
    # waited out the timeout and refused — while `doctor` still reported that
    # asks would reach a human.
    home = Path(tempfile.mkdtemp())
    d = subprocess.Popen([sys.executable, "-m", "airlock.askd", "--auto", "allow"],
                         env=_env(home), stderr=subprocess.DEVNULL)
    sock = home / "ask.sock"
    for _ in range(80):
        if sock.exists():
            break
        time.sleep(0.1)
    s.check("the daemon creates its socket", sock.exists())
    d.send_signal(signal.SIGTERM)
    try:
        d.wait(timeout=15)
        stopped = True
    except subprocess.TimeoutExpired:
        d.kill()
        d.wait()
        stopped = False
    time.sleep(0.5)
    s.check("SIGTERM stops the daemon", stopped)
    s.check("...and takes the socket with it", not sock.exists())

    # a socket left by a SIGKILL must not be mistaken for a reachable human
    home = Path(tempfile.mkdtemp())
    os.environ_backup = dict(os.environ)
    (home / "ask.sock").touch()
    saved = dict(os.environ)
    os.environ["AIRLOCK_HOME"] = str(home)
    try:
        import importlib
        from airlock import ask as askmod
        importlib.reload(askmod)
        s.check("a stale socket is not reported as a working ask channel",
                "socket" not in askmod.auto_backends(), askmod.auto_backends())
    finally:
        os.environ.clear()
        os.environ.update(saved)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
