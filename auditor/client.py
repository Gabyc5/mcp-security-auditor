"""
MCP JSON-RPC client.

Connects to an MCP server over HTTP and speaks the protocol:
- initialize (handshake)
- tools/list (discover tools)
- tools/call (invoke a tool)

This is the auditor's interface to the target server.
"""

import json
import requests
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MCPClient:
    """Lightweight MCP client for security scanning."""

    base_url: str
    timeout: float = 10.0
    headers: dict = field(default_factory=lambda: {"Content-Type": "application/json"})
    _request_id: int = 0
    _initialized: bool = False
    server_info: dict = field(default_factory=dict)

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _rpc(self, method: str, params: Optional[dict] = None) -> dict:
        """Send a JSON-RPC request and return the result."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id(),
        }
        resp = requests.post(
            self.base_url,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            raise MCPError(data["error"].get("code", -1), data["error"].get("message", "Unknown error"))

        return data.get("result", {})

    def initialize(self) -> dict:
        """Perform MCP initialize handshake."""
        result = self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-security-auditor", "version": "0.1.0"},
        })
        self._initialized = True
        self.server_info = result.get("serverInfo", {})
        return result

    def list_tools(self) -> list:
        """Call tools/list and return the list of tool definitions."""
        result = self._rpc("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Call a specific tool with arguments."""
        return self._rpc("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })

    def raw_post(self, body: bytes, headers: Optional[dict] = None) -> requests.Response:
        """Send a raw POST request (for transport-level checks)."""
        return requests.post(
            self.base_url,
            data=body,
            headers=headers or self.headers,
            timeout=self.timeout,
        )


class MCPError(Exception):
    """Error returned by an MCP server."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"MCP Error {code}: {message}")
