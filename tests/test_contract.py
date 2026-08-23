"""Contract test: a call the GLOBAL policy allows is still blocked when it
reaches outside the skill's own pinned contract (least-privilege grant)."""
import json, os, subprocess, sys, tempfile, pathlib, textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]


def rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m) + "\n"


def run(home, script):
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=home,
               AIRLOCK_POLICY=str(ROOT / "tests" / "fixtures" / "policy.yaml"), AIRLOCK_MODE="enforce")
    cmd = [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "demo",
           "--", sys.executable, str(ROOT / "examples" / "demo_server.py")]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    out, err = p.communicate(script.encode(), timeout=30)
    resp = {}
    for line in out.decode().splitlines():
        line = line.strip()
        if line:
            m = json.loads(line)
            if isinstance(m.get("id"), int):
                resp[m["id"]] = m
    return resp, err.decode()


def blocked(r, needle=""):
    return "error" in r and "airlock" in json.dumps(r["error"]).lower() and \
           (needle in json.dumps(r["error"]))


def main():
    home = tempfile.mkdtemp(prefix="airlock-contract-")
    # 1st run: pin the toolset (auto-derives a proposal contract, not enforced)
    run(home, rpc(1, "initialize", {}) + rpc(2, "tools/list", {}))
    # promote to an ENFORCED contract: read_note only, fs scoped to */notes/*
    contracts = pathlib.Path(home) / "contracts.yaml"
    contracts.write_text(textwrap.dedent("""\
        demo:
          enforced: true
          tools: [read_note]
          fs: ["*/notes/*"]
          net: []
          shell: false
          default: block
    """))
    # 2nd run: exercise the contract
    script = "".join([
        rpc(1, "initialize", {}),
        rpc(2, "tools/list", {}),
        # in-scope read -> allowed
        rpc(3, "tools/call", {"name": "read_note", "arguments": {"name": "/home/user/notes/todo"}}),
        # path escaping the contract scope -> blocked BY CONTRACT (global would allow read_note)
        rpc(4, "tools/call", {"name": "read_note", "arguments": {"name": "/home/user/../../etc/passwd"}}),
        # tool not in contract allow-list -> blocked
        rpc(5, "tools/call", {"name": "run_command", "arguments": {"command": "echo hi"}}),
    ])
    resp, err = run(home, script)

    checks = [
        ("in-scope read_note ALLOWED", "result" in resp.get(3, {})),
        ("out-of-scope path BLOCKED by contract", blocked(resp.get(4, {}), "outside contract scope")),
        ("tool not in contract BLOCKED", blocked(resp.get(5, {}), "not in pinned contract")),
    ]
    print("\n  CONTRACT TEST\n  " + "-" * 40)
    ok = True
    for n, r in checks:
        print(f"  [{'PASS' if r else 'FAIL'}] {n}"); ok = ok and r
    print("  " + "-" * 40)
    for l in err.splitlines():
        if "airlock" in l.lower():
            print("   ", l)
    print(f"\n  RESULT: {'ALL PASS' if ok else 'FAIL'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
