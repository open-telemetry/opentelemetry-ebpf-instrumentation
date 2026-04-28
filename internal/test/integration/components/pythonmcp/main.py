"""
MCP (Model Context Protocol) server for integration testing.

Uses the official MCP Python SDK (https://github.com/modelcontextprotocol/python-sdk)
to exercise a real end-to-end MCP stack over Streamable HTTP.
"""

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


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
