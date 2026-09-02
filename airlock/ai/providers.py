"""Bring-your-own model for the pro tier: provider presets + backend assembly.

A preset just prefills base_url (+ a sane default model); the user pastes their
key (stored via keys.py). Two adapters cover everyone — native Anthropic for
Claude, the OpenAI-compatible client for the rest and for any local server.

Cloud gating is enforced here: a cloud preset is refused unless `cloud: on`, and
`locked-off` can never be opened. Local presets (Ollama / a localhost custom
endpoint) are always allowed — nothing leaves the machine.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .anthropic import AnthropicBackend
from .keys import get_key
from .openai_compat import OpenAICompatBackend

# kind: "anthropic" | "openai"; local: nothing leaves the machine
PRESETS = {
    "claude":   {"kind": "anthropic", "base_url": "https://api.anthropic.com/v1", "model": "claude-3-5-haiku-latest", "local": False},
    "openai":   {"kind": "openai", "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini", "local": False},
    "deepseek": {"kind": "openai", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat", "local": False},
    "qwen":     {"kind": "openai", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen2.5-7b-instruct", "local": False},
    "kimi":     {"kind": "openai", "base_url": "https://api.moonshot.cn/v1", "model": "moonshot-v1-8k", "local": False},
    "glm":      {"kind": "openai", "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-4-flash", "local": False},
    "ollama":   {"kind": "openai", "base_url": "http://localhost:11434/v1", "model": "qwen2.5:3b", "local": True},
    "custom":   {"kind": "openai", "base_url": "", "model": "", "local": True},
}

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "")


def is_local(base_url: str) -> bool:
    try:
        return (urlparse(base_url).hostname or "") in _LOCAL_HOSTS
    except Exception:
        return False


def resolve(preset: str, base_url: str = "", model: str = "") -> dict | None:
    """Merge a preset with explicit overrides. None if the preset is unknown."""
    p = PRESETS.get(preset)
    if p is None:
        return None
    out = dict(p)
    if base_url:
        out["base_url"] = base_url
    if model:
        out["model"] = model
    # a custom/overridden endpoint is local iff its host is local
    if preset == "custom" or base_url:
        out["local"] = is_local(out["base_url"])
    return out


def backend_for(cfg):
    """Build the BYO backend from cfg.ai.provider, honoring cloud gating.

    Returns a Backend, or None if not configured, unknown, cloud-blocked, or
    missing a key. Never raises.
    """
    ai = getattr(cfg, "ai", {}) or {}
    prov = ai.get("provider") if isinstance(ai, dict) else None
    if not isinstance(prov, dict) or not prov.get("preset"):
        return None
    spec = resolve(prov.get("preset", ""), prov.get("base_url", ""), prov.get("model", ""))
    if spec is None or not spec.get("base_url") or not spec.get("model"):
        return None

    cloud = getattr(cfg, "cloud", "off")
    if not spec["local"] and cloud != "on":
        return None                       # cloud egress not permitted

    key = get_key(prov["preset"])
    if not spec["local"] and not key:
        return None                       # a cloud provider needs a key

    if spec["kind"] == "anthropic":
        return AnthropicBackend(spec["base_url"], spec["model"], api_key=key, source="cloud")
    return OpenAICompatBackend(spec["base_url"], spec["model"], api_key=key,
                               source=("mini" if spec["local"] else "cloud"),
                               local=spec["local"])
