"""`airlock bench` — the answer to "does it slow my agent down?".

Two numbers matter and they are different:
  decision   how long the policy engine takes to judge one call. This is the
             cost paid on the hook path, per native tool call.
  proxy      the end-to-end added latency of a tools/call travelling through the
             stdio MITM, measured against the same server without it.

Reported as p50/p99 because the mean hides the tail, and the tail is what a
person notices.
"""
from __future__ import annotations
import json
import os
try:
    import resource                  # POSIX-only; absent on Windows
except ModuleNotFoundError:          # pragma: no cover
    resource = None
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import config
from .policy import Policy

CASES = [
    ("Bash", {"command": "npm test -- --watch=false"}),
    ("Read", {"file_path": "src/components/App.tsx"}),
    ("Write", {"file_path": "src/x.ts", "content": "x" * 4000}),
    ("mcp__srv__fetch_url", {"url": "https://api.github.com/repos/o/r/pulls"}),
    ("mcp__srv__read_note", {"name": "todo", "meta": {"tags": ["a", "b"],
                                                      "note": "y" * 800}}),
]


def _pct(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = min(len(xs) - 1, int(round(q * (len(xs) - 1))))
    return xs[k]


def decision_latency(n: int = 2000) -> dict:
    pol = Policy.resolve()
    samples: list[float] = []
    for i in range(n):
        tool, args = CASES[i % len(CASES)]
        t0 = time.perf_counter()
        pol.decide(tool, args)
        samples.append((time.perf_counter() - t0) * 1e6)   # microseconds
    return {"n": n, "unit": "us",
            "p50": _pct(samples, 0.50), "p95": _pct(samples, 0.95),
            "p99": _pct(samples, 0.99), "max": max(samples),
            "mean": statistics.fmean(samples)}


_ECHO_SERVER = '''
import json, sys
T=[{"name":"ping","description":"ping","inputSchema":{"type":"object","properties":{}}}]
def h(m):
    i,me=m.get("id"),m.get("method")
    if me=="initialize": return {"jsonrpc":"2.0","id":i,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"e","version":"1"},"capabilities":{"tools":{}}}}
    if me=="tools/list": return {"jsonrpc":"2.0","id":i,"result":{"tools":T}}
    if me=="tools/call": return {"jsonrpc":"2.0","id":i,"result":{"content":[{"type":"text","text":"pong"}]}}
    if i is not None: return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"no"}}
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    m=json.loads(line)
    r=[x for x in (h(y) for y in m) if x] if isinstance(m,list) else h(m)
    if r: sys.stdout.write(json.dumps(r)+"\\n"); sys.stdout.flush()
'''


def _round_trip(cmd: list[str], n: int, env: dict) -> list[float]:
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env, bufsize=0)
    samples: list[float] = []
    try:
        def send(msg):
            p.stdin.write((json.dumps(msg) + "\n").encode())
            p.stdin.flush()

        def recv():
            return json.loads(p.stdout.readline().decode())

        send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}); recv()
        send({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}); recv()
        for i in range(n):
            msg = {"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                   "params": {"name": "ping", "arguments": {"i": i}}}
            t0 = time.perf_counter()
            send(msg)
            recv()
            samples.append((time.perf_counter() - t0) * 1000)   # ms
    finally:
        try:
            p.stdin.close()
            p.wait(timeout=5)
        except Exception:
            p.kill()
    return samples


def proxy_overhead(n: int = 300) -> dict:
    d = Path(tempfile.mkdtemp(prefix="airlock-bench-"))
    srv = d / "echo.py"
    srv.write_text(_ECHO_SERVER)
    base_env = dict(os.environ, AIRLOCK_HOME=str(d / "home"),
                    AIRLOCK_QUIET="1", AIRLOCK_MODE="guard",
                    PYTHONPATH=str(config.PKG.parent))
    direct = _round_trip([sys.executable, str(srv)], n, base_env)
    gated = _round_trip([sys.executable, "-m", "airlock.mcp_proxy",
                         "--server-id", "bench", "--", sys.executable, str(srv)],
                        n, base_env)
    return {
        "n": n, "unit": "ms",
        "direct": {"p50": _pct(direct, .5), "p99": _pct(direct, .99)},
        "gated": {"p50": _pct(gated, .5), "p99": _pct(gated, .99)},
        "added": {"p50": _pct(gated, .5) - _pct(direct, .5),
                  "p99": _pct(gated, .99) - _pct(direct, .99)},
    }


def memory() -> dict:
    if resource is None:             # Windows: no getrusage
        return {"rss_mb": None}
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS reports bytes
    mb = ru / 1024 if sys.platform != "darwin" else ru / (1024 * 1024)
    return {"rss_mb": round(mb, 1)}


def run(n_decisions: int = 2000, n_calls: int = 300) -> dict:
    return {"decision": decision_latency(n_decisions),
            "proxy": proxy_overhead(n_calls),
            "memory": memory(),
            "python": sys.version.split()[0],
            "platform": sys.platform}


def render(r: dict) -> str:
    d, p, m = r["decision"], r["proxy"], r["memory"]
    return "\n".join([
        "",
        "  AIRLOCK BENCHMARK",
        "  " + "-" * 58,
        f"  policy decision      p50 {d['p50']:7.1f} µs   p99 {d['p99']:7.1f} µs"
        f"   (n={d['n']})",
        f"  MCP call, direct     p50 {p['direct']['p50']:7.3f} ms   "
        f"p99 {p['direct']['p99']:7.3f} ms",
        f"  MCP call, gated      p50 {p['gated']['p50']:7.3f} ms   "
        f"p99 {p['gated']['p99']:7.3f} ms",
        f"  added by Airlock     p50 {p['added']['p50']:7.3f} ms   "
        f"p99 {p['added']['p99']:7.3f} ms   (n={p['n']})",
        f"  peak RSS             {m['rss_mb']} MB",
        "  " + "-" * 58,
        f"  python {r['python']} on {r['platform']}",
        "",
        "  For scale: a model turn is hundreds of ms at best. The gate is not",
        "  where your agent spends its time.",
        "",
    ])
