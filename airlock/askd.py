"""airlock-askd — the approval daemon.

Listens on $AIRLOCK_HOME/ask.sock. For each request from the proxy it pops a
zenity yes/no dialog and replies {"decision": "allow"|"block"}. This is the
"real ask channel": with it running, an `ask` verdict reaches a human instead
of collapsing to block.

    airlock-askd                 # GUI prompts via zenity
    airlock-askd --auto allow    # headless: auto-approve  (for tests/CI)
    airlock-askd --auto block    # headless: auto-deny
"""
from __future__ import annotations
import json
import os
import signal
import socket
import sys
import threading

from . import audit
from .ask import sock_path, _via_zenity
from .policy import ALLOW, BLOCK

TIMEOUT = float(os.environ.get("AIRLOCK_ASK_TIMEOUT", "60"))


def _handle(conn: socket.socket, auto: str | None):
    try:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        req = json.loads(buf.decode().strip() or "{}")
        if auto in (ALLOW, BLOCK):
            decision, via = auto, "auto"
        else:
            d = _via_zenity(req, TIMEOUT)
            decision = d if d in (ALLOW, BLOCK) else BLOCK
            via = "zenity" if d in (ALLOW, BLOCK) else "zenity-timeout->block"
        # Send first, then record what actually happened. Recording first meant
        # a human who answered after the caller had given up left "ask_prompt
        # effective=allow" in the log next to "decision effective=block" for
        # the same call — and the approval came second, so an auditor reading
        # in order saw the refusal overturned by an approval that was never
        # applied to anything. A log that records an approval for a call that
        # did not run is worse than no record: it invites the conclusion that
        # the action was authorised and happened.
        delivered = True
        try:
            conn.sendall((json.dumps({"decision": decision, "via": via}) + "\n").encode())
        except OSError:
            delivered = False
        if delivered:
            audit.record("ask_prompt", source="askd", server=req.get("server", ""),
                         tool=req.get("tool", ""), decision="ask", effective=decision,
                         reason=f"{req.get('reason','')} [{via}]")
        else:
            audit.record("ask_prompt", source="askd", server=req.get("server", ""),
                         tool=req.get("tool", ""), decision="ask", effective="flag",
                         reason=f"{req.get('reason','')} [{via}: answered "
                                f"'{decision}' too late — the caller had already "
                                f"given up, so this answer decided nothing]")
    except Exception as e:  # never crash the daemon on a bad request
        try:
            conn.sendall((json.dumps({"decision": BLOCK, "error": str(e)}) + "\n").encode())
        except Exception:
            pass
    finally:
        conn.close()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    auto = None
    if "--auto" in argv:
        i = argv.index("--auto")
        if i + 1 >= len(argv) or argv[i + 1] not in (ALLOW, BLOCK):
            print("airlock-askd: --auto needs 'allow' or 'block'", file=sys.stderr)
            return 2
        auto = argv[i + 1]
    if not hasattr(socket, "AF_UNIX"):
        print("airlock-askd: the approval daemon needs unix domain sockets, "
              "which this platform lacks. `ask` verdicts fall back to the "
              "policy's ask_fallback here; run the daemon under WSL if you want "
              "interactive approvals on Windows.", file=sys.stderr)
        return 2
    p = sock_path()
    if p.exists():
        p.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # umask before bind: chmod-after-bind leaves a window where any local user
    # can connect and answer approval prompts on your behalf.
    old = os.umask(0o177)
    try:
        srv.bind(str(p))
    finally:
        os.umask(old)
    os.chmod(p, 0o600)
    srv.listen(16)
    mode = f"auto={auto}" if auto else "zenity GUI"
    print(f"[airlock-askd] listening on {p}  ({mode})", file=sys.stderr, flush=True)
    # A supervisor sends SIGTERM, not ^C. Without a handler the default action
    # killed the daemon outright and the socket stayed on disk — after which
    # every `ask` connected to nothing, waited out the timeout and refused,
    # while `airlock doctor` still reported that asks would reach a human.
    def bye(signum, _frame):
        raise KeyboardInterrupt
    for signame in ("SIGTERM", "SIGHUP"):          # SIGHUP does not exist on Windows
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, bye)
        except (ValueError, OSError):
            pass

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_handle, args=(conn, auto), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        if p.exists():
            p.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
