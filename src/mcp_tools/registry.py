"""Remediation tools exposed to the Remediator agent (MCP-style).

Each tool is a named, described, JSON-schema'd capability with a ``destructive``
flag. Destructive tools (disable a credential, block an IP, revoke sessions, isolate
a host) are gated by the human-in-the-loop guardrail before they run. The
implementations here are mocked: they return a simulated result instead of touching
any real system, which is enough to demonstrate the agent + MCP + approval flow.

The same registry can be served over a real MCP transport via ``server.py`` (optional,
requires FastMCP), so the agent could later call the tools through an MCP gateway.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


def _object_schema(**properties: dict[str, str]) -> dict[str, Any]:
    """Minimal JSON-schema object; every listed property is required."""
    return {
        "type": "object",
        "properties": {name: {"type": "string", "description": desc} for name, desc in properties.items()},
        "required": list(properties),
    }


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema (object)
    destructive: bool
    run: Callable[[dict[str, Any]], dict[str, Any]]

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "destructive": self.destructive,
            "parameters": self.parameters,
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools)

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.schema() for tool in self._tools.values()]


def _simulate(action: str, args: dict[str, Any]) -> dict[str, Any]:
    """Return a simulated result; no real system is touched."""
    return {"status": "simulated", "action": action, "args": args}


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()

    registry.register(
        Tool(
            name="disable_credential",
            description="Disable a compromised credential or access key so it can no longer be used.",
            parameters=_object_schema(
                principal="identity that owns the credential",
                credential_id="id of the key or credential to disable",
            ),
            destructive=True,
            run=lambda args: _simulate("disable_credential", args),
        )
    )
    registry.register(
        Tool(
            name="block_ip",
            description="Block a source IP address at the firewall or perimeter.",
            parameters=_object_schema(
                ip="source IP address to block",
                duration_hours="how long to block it (hours)",
            ),
            destructive=True,
            run=lambda args: _simulate("block_ip", args),
        )
    )
    registry.register(
        Tool(
            name="revoke_sessions",
            description="Revoke all active sessions for an identity to invalidate stolen tokens.",
            parameters=_object_schema(principal="identity whose sessions to revoke"),
            destructive=True,
            run=lambda args: _simulate("revoke_sessions", args),
        )
    )
    registry.register(
        Tool(
            name="isolate_host",
            description="Isolate a host from the network to stop a threat from spreading.",
            parameters=_object_schema(host_id="identifier of the host to isolate"),
            destructive=True,
            run=lambda args: _simulate("isolate_host", args),
        )
    )
    registry.register(
        Tool(
            name="create_ticket",
            description="Open an incident ticket to track the investigation and response.",
            parameters=_object_schema(
                title="short ticket title",
                severity="incident severity (e.g. low, medium, high, critical)",
            ),
            destructive=False,
            run=lambda args: _simulate("create_ticket", args),
        )
    )
    registry.register(
        Tool(
            name="notify",
            description="Send a notification to a team or channel.",
            parameters=_object_schema(
                channel="team or channel to notify",
                message="message to send",
            ),
            destructive=False,
            run=lambda args: _simulate("notify", args),
        )
    )
    return registry
