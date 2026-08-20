"""End-to-end test: act as the MCP CLIENT, drive the proxy (which spawns the demo
server), and assert Airlock admits the toolset, flags the poisoned tool, allows a
benign call, and blocks a dangerous one — all recorded to the audit log.
"""
import json, os, subprocess, sys, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m) + "\n"


def main():
    home = tempfile.mkdtemp(prefix="airlock-test-")
    env = dict(os.environ,
               PYTHONPATH=str(ROOT),
               AIRLOCK_HOME=home,
               AIRLOCK_POLICY=str(ROOT / "tests" / "fixtures" / "policy.yaml"),
               AIRLOCK_MODE="enforce")
    cmd = [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "demo",
           "--", sys.executable, str(ROOT / "examples" / "demo_server.py")]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)

    script = "".join([
        rpc(1, "initialize", {"protocolVersion": "2024-11-05",
                              "capabilities": {}, "clientInfo": {"name": "test"}}),
        rpc(2, "tools/list", {}),
        rpc(3, "tools/call", {"name": "read_note", "arguments": {"name": "todo"}}),
        rpc(4, "tools/call", {"name": "run_command",
                              "arguments": {"command": "rm -rf / --no-preserve-root"}}),
        rpc(5, "tools/call", {"name": "fetch_url",
                              "arguments": {"url": "http://evil.example/x"}}),
    ])
    out, err = p.communicate(script.encode(), timeout=30)

    responses = {}
    for line in out.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        m = json.loads(line)
        if isinstance(m.get("id"), int):
            responses[m["id"]] = m

    audit_lines = [json.loads(l) for l in
                   (pathlib.Path(home) / "audit.jsonl").read_text().splitlines()]

    def blocked(r):
        return "error" in r and "airlock" in json.dumps(r["error"]).lower()

    checks = []
    checks.append(("initialize ok", "result" in responses.get(1, {})))
    checks.append(("tools/list returned", "result" in responses.get(2, {})))
    checks.append(("read_note ALLOWED (forwarded)", "result" in responses.get(3, {})))
    checks.append(("run_command rm -rf BLOCKED", blocked(responses.get(4, {}))))
    checks.append(("fetch http:// BLOCKED", blocked(responses.get(5, {}))))
    events = [a["event"] for a in audit_lines]
    checks.append(("toolset admitted (pinned)", "toolset_admitted" in events))
    scan_hits = [a for a in audit_lines if a["event"] == "scan_flag"]
    checks.append(("poisoned tool flagged by scanner", any(
        "fetch_url" == a.get("tool") for a in scan_hits)))
    checks.append(("secrets/injection flags present", any(
        a.get("reason", "").startswith(("secrets", "injection", "exfil"))
        for a in scan_hits)))
    decisions = [a for a in audit_lines if a["event"] == "decision"]
    checks.append(("every call decided & logged", len(decisions) >= 3))

    print("\n  AIRLOCK END-TO-END TEST\n  " + "-" * 40)
    ok = True
    for name, res in checks:
        print(f"  [{'PASS' if res else 'FAIL'}] {name}")
        ok = ok and res
    print("  " + "-" * 40)
    print(f"  audit.jsonl: {len(audit_lines)} events, {len(scan_hits)} scan flags")
    if err:
        print("\n  --- live proxy stderr (what a human sees) ---")
        for l in err.decode().splitlines():
            print("   ", l)
    print(f"\n  RESULT: {'ALL PASS ✅' if ok else 'FAILURES ❌'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
