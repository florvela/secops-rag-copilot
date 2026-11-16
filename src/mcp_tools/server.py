"""Optional: expose the remediation tools over a real MCP transport.

This lets the tools be consumed by any MCP client (Claude Desktop, an IDE, a custom
agent) or fronted by an MCP gateway. It is optional and not on the default runtime
path — the orchestrator calls the registry in-process. Requires FastMCP:

    pip install fastmcp
    python -m src.mcp_tools.server   # starts a stdio MCP server
"""

from __future__ import annotations

from src.mcp_tools.registry import ToolRegistry, build_default_registry


def build_mcp_server(registry: ToolRegistry | None = None):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "FastMCP is not installed. Run `pip install fastmcp` to serve the "
            "remediation tools over MCP."
        ) from exc

    registry = registry or build_default_registry()
    server = FastMCP("secops-remediation")
    for tool in registry.all():
        server.add_tool(
            tool.run,
            name=tool.name,
            description=f"{tool.description} (destructive={tool.destructive})",
        )
    return server


if __name__ == "__main__":  # pragma: no cover
    build_mcp_server().run()
