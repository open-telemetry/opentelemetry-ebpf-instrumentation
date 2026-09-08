"""
MCP (Model Context Protocol) server for integration testing.

Uses the official MCP Python SDK (https://github.com/modelcontextprotocol/python-sdk)
to exercise a real end-to-end MCP stack over Streamable HTTP.
"""

import os

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="test-mcp-server",
    host="0.0.0.0",
    port=8080,
    streamable_http_path="/mcp",
)


@mcp.tool(name="get-weather", description="Get weather information")
def get_weather() -> str:
    """Returns weather data for the requested location."""
    return "Sunny, 72°F in the requested location"


@mcp.tool(name="calculator", description="Simple calculator")
def calculator() -> str:
    """Returns calculation result."""
    return "42"


@mcp.resource("file:///home/user/documents/report.pdf")
def read_report() -> str:
    """Sample report content."""
    return "Sample report content"


@mcp.prompt(name="analyze-code", description="Analyzes code for potential issues")
def analyze_code() -> str:
    """Code analysis prompt."""
    return "Analyze this code"


# Calling out to a second MCP server makes this process an MCP *client* as
# well as a server, which is what produces a client-kind MCP span.
REMOTE_MCP_URL = os.environ.get("REMOTE_MCP_URL", "http://mcpremote:8080/mcp")


@mcp.tool(name="remote-weather", description="Get weather from a remote MCP server")
async def remote_weather() -> str:
    """Calls get-weather on the remote MCP server and returns its answer."""
    async with streamablehttp_client(REMOTE_MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-weather", {})
            return result.content[0].text if result.content else ""


@mcp.tool(name="remote-report", description="Read a report from a remote MCP server")
async def remote_report() -> str:
    """Reads a resource from the remote MCP server and returns its content."""
    async with streamablehttp_client(REMOTE_MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.read_resource(
                "file:///home/user/documents/report.pdf"
            )
            return result.contents[0].text if result.contents else ""


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
