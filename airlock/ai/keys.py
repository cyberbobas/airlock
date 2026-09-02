"""API-key storage for the pro tier — OS keychain first, never plaintext config.

Airlock flags plaintext credentials in agent configs (agentpipe LOC-06); it would
be embarrassing to store its own keys in the clear. So keys go in the OS keychain
(macOS Keychain / Windows Credential Manager / libsecret) via `keyring` when it
is installed. If it is not, we fall back to a 0600 file under $AIRLOCK_HOME and
say so loudly — that is a degraded mode, not the intended one.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .. import audit

SERVICE = "airlock-ai"

try:
    import keyring as _keyring  # optional dependency
except Exception:
    _keyring = None


def _file() -> Path:
    return audit.home() / "ai-keys.json"


def _warn_once():
    if not os.environ.get("_AIRLOCK_KEYRING_WARNED"):
        sys.stderr.write(
            "airlock: python 'keyring' not installed — storing the API key in a "
            "0600 file under $AIRLOCK_HOME instead of the OS keychain. "
            "Install keyring for secure storage.\n")
        os.environ["_AIRLOCK_KEYRING_WARNED"] = "1"


def _load_file() -> dict:
    p = _file()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_file(d: dict) -> None:
    p = _file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def set_key(provider: str, key: str) -> None:
    if _keyring is not None:
        _keyring.set_password(SERVICE, provider, key)
        return
    _warn_once()
    d = _load_file(); d[provider] = key; _save_file(d)


def get_key(provider: str) -> str:
    if _keyring is not None:
        try:
            return _keyring.get_password(SERVICE, provider) or ""
        except Exception:
            return ""
    return _load_file().get(provider, "")


def has_key(provider: str) -> bool:
    return bool(get_key(provider))


def delete_key(provider: str) -> None:
    if _keyring is not None:
        try:
            _keyring.delete_password(SERVICE, provider)
        except Exception:
            pass
        return
    d = _load_file()
    if provider in d:
        del d[provider]; _save_file(d)
