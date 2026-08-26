"""Cross-platform smoke test — the core path on any OS, Windows included.

The full suite leans on POSIX helpers (shell-script fakes, unix sockets, /dev/tty)
that do not exist on Windows. This file exercises only what must work everywhere:
import, the CLI entry points, and one real gated decision. It is what the Windows
CI job runs, so a green Windows badge means these actually pass there.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
FAILED = []


def run(args, env, expect=None):
    # decode the child's UTF-8 output as UTF-8, not the Windows locale (cp1252),
    # which cannot decode the glyphs the CLI prints.
    r = subprocess.run([PY, "-m", "airlock.cli", *args], env=env,
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if expect is not None and r.returncode != expect:
        FAILED.append(f"airlock {' '.join(args)} -> exit {r.returncode} "
                      f"(expected {expect})\n{r.stdout[-300:]}\n{r.stderr[-300:]}")
    return r


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILED.append(f"{name}: {detail}")


def main():
    print("AIRLOCK SMOKE  (cross-platform core)")
    import airlock                                          # import must work
    check("package imports", bool(airlock.__version__), airlock.__version__)

    home = Path(tempfile.mkdtemp(prefix="airlock-smoke-"))
    proj = home / "proj"; proj.mkdir()
    env = dict(os.environ, PYTHONPATH=str(ROOT), HOME=str(home),
               USERPROFILE=str(home), AIRLOCK_HOME=str(home / ".airlock"),
               AIRLOCK_WORKSPACE=str(proj),
               CLAUDE_SETTINGS=str(home / "settings.json"),
               AIRLOCK_NOTIFY="0", AIRLOCK_QUIET="1")

    check("--version", run(["--version"], env, 0).returncode == 0)

    # a dangerous native call is BLOCKED (exit 1)
    r = run(["check", "Bash", json.dumps({"command": "rm -rf / --no-preserve-root"})], env)
    check("check blocks rm -rf /", r.returncode == 1, r.stdout[-200:])

    # scanning the bundled poisoned skill flags high severity (exit 1)
    from airlock import demo as _demo
    r = run(["scan", str(_demo._SKILL), "--fail-on-findings", "--no-color"], env)
    check("scan flags the poisoned skill", r.returncode == 1, r.stdout[-200:])

    # the self-contained demo blocks the exfil and keeps the chain intact
    r = run(["demo", "--no-color"], env, 0)
    check("demo blocks exfil + chain intact",
          "BLOCK" in r.stdout and "CHAIN INTACT" in r.stdout, r.stdout[-300:])

    # init -> doctor -> uninstall round trip (no MCP stores present here)
    (proj / ".mcp.json").write_text('{"mcpServers":{"t":{"command":"uvx","args":["x"]}}}')
    check("init exits clean", run(["init", "--profile", "default"], env, 0).returncode == 0)
    check("init wrapped the project store",
          "_airlock_original" in (proj / ".mcp.json").read_text())
    run(["doctor"], env)                                   # must not crash
    check("uninstall exits clean", run(["uninstall", "-y"], env, 0).returncode == 0)
    check("uninstall restored the store",
          "_airlock_original" not in (proj / ".mcp.json").read_text())

    print()
    if FAILED:
        print(f"SMOKE FAILED ({len(FAILED)}):")
        for f in FAILED:
            print("  - " + f)
        return 1
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
