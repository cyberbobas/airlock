"""Ask-channel test: with the daemon running, an `ask` verdict is resolved by
the daemon (allow/block) instead of collapsing to block. Uses --auto so it runs
headless; the real daemon uses a zenity dialog instead."""
import json, os, subprocess, sys, tempfile, pathlib, time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m) + "\n"


def proxy_call(home, backend):
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=home,
               AIRLOCK_POLICY=str(ROOT / "tests" / "fixtures" / "policy.yaml"), AIRLOCK_MODE="enforce",
               AIRLOCK_ASK_BACKEND=backend, AIRLOCK_ASK_TIMEOUT="10")
    cmd = [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "demo",
           "--", sys.executable, str(ROOT / "examples" / "demo_server.py")]
    # run_command with a benign command -> global policy says `ask`
    script = (rpc(1, "initialize", {}) + rpc(2, "tools/list", {}) +
              rpc(3, "tools/call", {"name": "run_command",
                                    "arguments": {"command": "echo hi"}}))
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    out, err = p.communicate(script.encode(), timeout=30)
    resp = {}
    for line in out.decode().splitlines():
        if line.strip():
            m = json.loads(line)
            if isinstance(m.get("id"), int):
                resp[m["id"]] = m
    return resp, err.decode()


def start_daemon(home, auto):
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=home)
    d = subprocess.Popen([sys.executable, "-m", "airlock.askd", "--auto", auto],
                         env=env, stderr=subprocess.PIPE)
    # wait for the socket to appear
    sock = pathlib.Path(home) / "ask.sock"
    for _ in range(50):
        if sock.exists():
            break
        time.sleep(0.1)
    return d


def main():
    ok = True
    print("\n  ASK-CHANNEL TEST\n  " + "-" * 44)

    # A) no daemon, backend=fallback -> ask collapses to block (fail-safe)
    home = tempfile.mkdtemp(prefix="airlock-ask-")
    resp, _ = proxy_call(home, "fallback")
    a = "error" in resp.get(3, {}) and "airlock" in json.dumps(resp[3]).lower()
    print(f"  [{'PASS' if a else 'FAIL'}] no daemon: ask -> BLOCK (fail-safe)")
    ok = ok and a

    # B) daemon --auto allow -> ask resolves to ALLOW (forwarded)
    home = tempfile.mkdtemp(prefix="airlock-ask-")
    d = start_daemon(home, "allow")
    resp, err = proxy_call(home, "socket")
    b = "result" in resp.get(3, {})
    print(f"  [{'PASS' if b else 'FAIL'}] daemon allow: ask -> ALLOW (forwarded)")
    ok = ok and b
    d.terminate()

    # C) daemon --auto block -> ask resolves to BLOCK
    home = tempfile.mkdtemp(prefix="airlock-ask-")
    d = start_daemon(home, "block")
    resp, err = proxy_call(home, "socket")
    c = "error" in resp.get(3, {}) and "airlock" in json.dumps(resp.get(3, {})).lower()
    print(f"  [{'PASS' if c else 'FAIL'}] daemon block: ask -> BLOCK")
    ok = ok and c
    d.terminate()

    print("  " + "-" * 44)
    print(f"\n  RESULT: {'ALL PASS' if ok else 'FAIL'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
