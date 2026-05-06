"""
Transport security checks.

TRANSPORT-001: No TLS (plain HTTP)
TRANSPORT-002: Missing or overly permissive CORS
"""

import requests
from urllib.parse import urlparse
from auditor.models import Finding, CheckResult, Severity
from auditor.client import MCPClient


def check_no_tls(client: MCPClient) -> CheckResult:
    """
    TRANSPORT-001: Check if the server accepts unencrypted HTTP.
    
    If the MCP server serves over plain HTTP, all traffic (including
    auth tokens, tool call arguments, and responses) is visible to
    anyone sniffing the network.
    """
    findings = []
    parsed = urlparse(client.base_url)

    if parsed.scheme == "http":
        findings.append(Finding(
            check_id="TRANSPORT-001",
            title="Server accessible over plain HTTP (no TLS)",
            severity=Severity.HIGH,
            description=(
                f"The server at {client.base_url} is accessible over unencrypted HTTP. "
                "All MCP traffic, including authentication tokens, tool call arguments, "
                "and responses, is transmitted in plaintext and can be intercepted by "
                "anyone on the network path."
            ),
            evidence=f"URL scheme: {parsed.scheme}",
            remediation=(
                "Serve the MCP server over HTTPS with a valid TLS certificate. "
                "For local development, use a reverse proxy (e.g., Cloudflare Tunnel, "
                "Caddy, or nginx) that terminates TLS. Reject plain HTTP connections "
                "or redirect them to HTTPS."
            ),
        ))

    return CheckResult(
        check_id="TRANSPORT-001",
        passed=len(findings) == 0,
        findings=findings,
    )


def check_cors(client: MCPClient) -> CheckResult:
    """
    TRANSPORT-002: Check CORS configuration.
    
    If the server returns Access-Control-Allow-Origin: * on preflight,
    any website in the user's browser can make requests to the MCP server.
    This enables browser-based attacks.
    """
    findings = []

    try:
        resp = requests.options(
            client.base_url,
            headers={
                "Origin": "https://evil-attacker-site.example.com",
                "Access-Control-Request-Method": "POST",
            },
            timeout=client.timeout,
        )

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            findings.append(Finding(
                check_id="TRANSPORT-002",
                title="Wildcard CORS: server allows requests from any origin",
                severity=Severity.HIGH,
                description=(
                    "The server returns 'Access-Control-Allow-Origin: *', meaning "
                    "any website can make requests to this MCP server from a user's browser. "
                    "An attacker could host a malicious page that calls your MCP tools "
                    "using the victim's browser session."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation=(
                    "Set Access-Control-Allow-Origin to the specific domain(s) that "
                    "need access. Never use wildcard (*) in production."
                ),
            ))
        elif acao == "https://evil-attacker-site.example.com":
            findings.append(Finding(
                check_id="TRANSPORT-002",
                title="CORS reflects arbitrary origin",
                severity=Severity.CRITICAL,
                description=(
                    "The server reflects the requesting origin in its CORS headers, "
                    "effectively allowing any origin. This is worse than a wildcard "
                    "because it also works with credentialed requests."
                ),
                evidence=f"Reflected origin: {acao}",
                remediation=(
                    "Validate the Origin header against a strict allowlist. "
                    "Never reflect the origin directly."
                ),
            ))
    except Exception:
        pass

    return CheckResult(
        check_id="TRANSPORT-002",
        passed=len(findings) == 0,
        findings=findings,
    )


def run_transport_checks(client: MCPClient) -> list:
    """Run all transport checks. Returns list of CheckResult."""
    return [
        check_no_tls(client),
        check_cors(client),
    ]
