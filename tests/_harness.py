"""Shared test harness: drive the proxy as if we were the MCP client."""
import json, os, subprocess, sys, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Tests must NEVER touch the developer's desktop. Several suites drive the proxy
# and hook through hundreds of blocks; with notify-send installed and a DISPLAY
# present that meant a burst of real toasts on every run. Every test module
# imports this harness, so forcing these off once — before any suite builds a
# subprocess env from os.environ — keeps the whole test tree silent. A test that
# genuinely exercises the ask channel sets AIRLOCK_ASK_BACKEND in its own env.
os.environ["AIRLOCK_NOTIFY"] = "0"
os.environ.setdefault("AIRLOCK_ASK_BACKEND", "fallback")


def rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m) + "\n"


def call(i, name, args):
    return rpc(i, "tools/call", {"name": name, "arguments": args})


HANDSHAKE = rpc(1, "initialize", {}) + rpc(2, "tools/list", {})


def drive(script, *, home=None, server_id="demo", server=None, mode="enforce",
          env_extra=None, timeout=30):
    """Run the proxy over `script`; return (responses_by_id, stderr, home)."""
    home = home or tempfile.mkdtemp(prefix="airlock-t-")
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=home,
               AIRLOCK_POLICY=str(ROOT / "tests" / "fixtures" / "policy.yaml"), AIRLOCK_MODE=mode,
               AIRLOCK_NOTIFY="0", AIRLOCK_ASK_BACKEND="fallback")
    env.pop("AIRLOCK_QUIET", None)
    if env_extra:
        env.update(env_extra)
    server = server or str(ROOT / "examples" / "demo_server.py")
    cmd = [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", server_id,
           "--", sys.executable, server]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    try:
        out, err = p.communicate(script.encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        raise AssertionError("proxy hung — the gate stopped answering")
    resp = {}
    for line in out.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        for item in (m if isinstance(m, list) else [m]):
            if isinstance(item, dict) and isinstance(item.get("id"), int):
                resp[item["id"]] = item
    return resp, err.decode(), home


def forwarded(r):
    return "result" in (r or {})


def blocked(r, needle=""):
    r = r or {}
    return ("error" in r and "airlock" in json.dumps(r["error"]).lower()
            and needle.lower() in json.dumps(r["error"]).lower())


def audit_events(home):
    p = pathlib.Path(home) / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


class Suite:
    def __init__(self, title):
        self.title = title
        self.rows = []

    def check(self, name, ok, note=""):
        self.rows.append((name, bool(ok), note))
        return bool(ok)

    def report(self):
        print(f"\n  {self.title}\n  " + "-" * 62)
        ok = True
        for name, res, note in self.rows:
            print(f"  [{'PASS' if res else 'FAIL'}] {name}" + (f"  {note}" if note and not res else ""))
            ok = ok and res
        print("  " + "-" * 62)
        print(f"  RESULT: {'ALL PASS' if ok else 'FAILURES'}  "
              f"({sum(1 for _, r, _ in self.rows if r)}/{len(self.rows)})\n")
        return 0 if ok else 1
