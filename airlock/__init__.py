"""Airlock — a minimal runtime firewall for AI coding agents.

Two enforcement points share one policy engine:
  * mcp_proxy — a stdio man-in-the-middle for MCP servers (planes 4 + 2)
  * cc_hook   — a Claude Code PreToolUse hook for the agent's native tools (plane 2)
"""
# Single source of truth is pyproject; read it from the installed metadata so
# `airlock --version` can never drift from the released package again. The
# fallback covers running from a source tree that was never `pip install`ed.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version
    try:
        __version__ = _pkg_version("airlock-agent")
    except PackageNotFoundError:
        __version__ = "0.0.0+source"
except Exception:  # pragma: no cover - importlib.metadata always present on 3.8+
    __version__ = "0.0.0+source"
