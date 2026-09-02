"""The built-in ("standard" tier) brain: our own model, shipped as a llamafile.

A llamafile is a single self-contained executable: the model weights + the
llama.cpp runtime + an OpenAI-compatible server, in one file, no install, no
Python/CUDA/Ollama for the user. Airlock manages its lifecycle and talks to it
over localhost with the shared OpenAI-compatible client.

The model is Qwen2.5-3B-Instruct (Apache-2.0) by default — small enough to run on
CPU on the hot path, permissively licensed so we can fine-tune it, merge, requant
to GGUF and ship our own judge (see training/). Swappable via env / config.

Resolution order for where the model lives / runs:
  1. AIRLOCK_AI_URL   — a base URL of an already-running OpenAI-compatible server
                        (dev, power users, or a managed sidecar). Skips spawning.
  2. AIRLOCK_AI_MODEL — path to a .llamafile to run ourselves.
  3. $AIRLOCK_HOME/models/*.llamafile — the shipped/downloaded model.
If none is present, `available()` is False and callers use the non-AI path.
"""
from __future__ import annotations

import os
import subprocess
import time
import urllib.request
from pathlib import Path

from .. import audit
from .openai_compat import OpenAICompatBackend

URL_ENV = "AIRLOCK_AI_URL"
MODEL_ENV = "AIRLOCK_AI_MODEL"
MODEL_NAME_ENV = "AIRLOCK_AI_MODEL_NAME"
PORT = int(os.environ.get("AIRLOCK_AI_PORT", "8231"))

# One spawned server per process, remembered so we do not fork on every gate.
_SERVER_STARTED = False


def models_dir() -> Path:
    return audit.home() / "models"


def model_path() -> Path | None:
    """The llamafile to run, or None if the model is not installed."""
    p = os.environ.get(MODEL_ENV)
    if p:
        q = Path(p)
        return q if q.exists() else None
    d = models_dir()
    if d.exists():
        found = sorted(d.glob("*.llamafile"))
        if found:
            return found[0]
    return None


def _port_alive(port: int, timeout: float = 0.25) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models",
                                    timeout=timeout):
            return True
    except Exception:
        return False


def _ensure_server(mf: Path, port: int) -> bool:
    """Start the llamafile server once if it is not already answering."""
    global _SERVER_STARTED
    if _port_alive(port):
        return True
    if _SERVER_STARTED:
        # We started it; give a just-launched server a brief moment.
        for _ in range(20):
            if _port_alive(port):
                return True
            time.sleep(0.25)
        return _port_alive(port)
    try:
        os.chmod(mf, 0o755)
    except Exception:
        pass
    try:
        subprocess.Popen(
            [str(mf), "--server", "--host", "127.0.0.1", "--port", str(port),
             "--nobrowser"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _SERVER_STARTED = True
    except Exception:
        return False
    for _ in range(40):   # up to ~10s for first cold start
        if _port_alive(port):
            return True
        time.sleep(0.25)
    return False


class BuiltinBackend(OpenAICompatBackend):
    """Our shipped model, run locally via llamafile. 100% offline."""

    def __init__(self):
        url = (os.environ.get(URL_ENV) or "").rstrip("/")
        super().__init__(
            base_url=url or f"http://127.0.0.1:{PORT}/v1",
            model=os.environ.get(MODEL_NAME_ENV, "airlock-judge"),
            source="mini",
            local=True,
        )
        self._explicit_url = bool(url)

    def available(self) -> bool:
        # No network round-trip on the hot path: a running URL, or a model file
        # on disk, is enough to consider ourselves usable. The actual call still
        # fails safe (returns None / "") if the server does not answer in time.
        if self._explicit_url:
            return True
        return model_path() is not None

    def _ensure(self) -> bool:
        if self._explicit_url:
            return True
        mf = model_path()
        return bool(mf) and _ensure_server(mf, PORT)

    def judge(self, ctx, *, timeout_ms):
        if not self._ensure():
            return None
        return super().judge(ctx, timeout_ms=timeout_ms)

    def summarize(self, facts: dict, *, timeout_ms: int = 20000) -> str:
        if not self._ensure():
            return ""
        return super().summarize(facts, timeout_ms=timeout_ms)
