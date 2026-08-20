"""Airlock — a minimal runtime firewall for AI coding agents.

Two enforcement points share one policy engine:
  * mcp_proxy — a stdio man-in-the-middle for MCP servers (planes 4 + 2)
  * cc_hook   — a Claude Code PreToolUse hook for the agent's native tools (plane 2)
"""
__version__ = "0.4.2"
