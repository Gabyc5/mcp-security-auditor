"""
Authentication checks.

AUTH-001: No authentication required
AUTH-002: Weak/default credentials accepted
"""

from auditor.models import Finding, CheckResult, Severity
from auditor.client import MCPClient, MCPError


def check_no_auth(client: MCPClient) -> CheckResult:
    """
    AUTH-001: Test if the server accepts unauthenticated requests.
    
    Connects without any credentials and tries to:
    1. Initialize the connection
    2. List available tools
    3. Call a tool
    
    If any of these succeed, the server has no auth.
    """
    findings = []

    # Try initialize without auth
    try:
        result = client.initialize()
        findings.append(Finding(
            check_id="AUTH-001",
            title="Server accepts unauthenticated connections",
            severity=Severity.CRITICAL,
            description=(
                "The MCP server completed the initialize handshake without requiring "
                "any authentication. Any client on the network can connect and discover "
                "available tools."
            ),
            evidence=f"Server responded with: {result.get('serverInfo', {})}",
            remediation=(
                "Implement authentication on the MCP server. Options include: "
                "OAuth 2.0/OIDC bearer tokens, mutual TLS (mTLS), or API key "
                "validation. The MCP spec does not mandate a specific auth mechanism, "
                "so this must be implemented at the server level."
            ),
        ))
    except Exception:
        return CheckResult(check_id="AUTH-001", passed=True)

    # Try listing tools without auth
    try:
        tools = client.list_tools()
        if tools:
            findings.append(Finding(
                check_id="AUTH-001",
                title="Tools enumerable without authentication",
                severity=Severity.HIGH,
                description=(
                    f"Successfully enumerated {len(tools)} tools without any credentials. "
                    f"Tool names: {', '.join(t['name'] for t in tools)}. "
                    "An attacker can map the entire attack surface."
                ),
                evidence=f"Discovered {len(tools)} tools",
                remediation="Require authentication before allowing tools/list calls.",
            ))
    except Exception:
        pass

    # Try calling a tool without auth
    if tools:
        safe_tool = next((t for t in tools if t["name"] == "echo"), tools[0])
        try:
            result = client.call_tool(safe_tool["name"], {"message": "auth_test"})
            findings.append(Finding(
                check_id="AUTH-001",
                title="Tool execution without authentication",
                severity=Severity.CRITICAL,
                description=(
                    f"Successfully called tool '{safe_tool['name']}' without credentials. "
                    "Any network-reachable client can execute server-side operations."
                ),
                evidence=f"Tool '{safe_tool['name']}' returned a response",
                remediation=(
                    "Enforce authentication on all tools/call requests. Consider "
                    "per-tool authorization policies."
                ),
                cve_refs=["CVE-2025-49596"],
            ))
        except Exception:
            pass

    return CheckResult(
        check_id="AUTH-001",
        passed=len(findings) == 0,
        findings=findings,
    )


def check_weak_credentials(client: MCPClient, tools: list) -> CheckResult:
    """
    AUTH-002: Test common weak credentials.
    
    Tries connecting with common default API keys and tokens
    to see if the server accepts them.
    """
    findings = []
    weak_tokens = [
        "",
        "test",
        "admin",
        "password",
        "sk-test-1234",
        "bearer token",
        "api_key",
        "default",
    ]

    for token in weak_tokens:
        try:
            test_client = MCPClient(
                base_url=client.base_url,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}" if token else "",
                },
            )
            result = test_client.initialize()
            if result:
                findings.append(Finding(
                    check_id="AUTH-002",
                    title=f"Server accepts weak credential: '{token or '(empty)'}'",
                    severity=Severity.HIGH if token else Severity.CRITICAL,
                    description=(
                        f"The server accepted authentication with "
                        f"{'an empty token' if not token else f'the weak token \"{token}\"'}. "
                        "This suggests either no auth validation or acceptance of default credentials."
                    ),
                    remediation=(
                        "Validate credentials against a secure identity provider. "
                        "Reject empty, default, and commonly-used test tokens."
                    ),
                ))
                break  # One finding is enough to prove the point
        except Exception:
            continue

    return CheckResult(
        check_id="AUTH-002",
        passed=len(findings) == 0,
        findings=findings,
    )


def run_auth_checks(client: MCPClient, tools: list) -> list:
    """Run all authentication checks. Returns list of CheckResult."""
    return [
        check_no_auth(client),
        check_weak_credentials(client, tools),
    ]
