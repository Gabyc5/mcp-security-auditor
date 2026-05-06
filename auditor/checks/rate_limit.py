"""
Rate limiting checks.

RATE-001: No rate limiting on tool calls
"""

import time
from auditor.models import Finding, CheckResult, Severity
from auditor.client import MCPClient


def check_rate_limiting(client: MCPClient, tools: list) -> CheckResult:
    """
    RATE-001: Test if the server enforces rate limiting.
    
    Sends a burst of rapid requests and checks if any are throttled.
    No rate limiting means:
    - Denial of service is trivial
    - Brute force attacks on any auth are feasible
    - Data can be extracted at machine speed
    """
    findings = []
    burst_count = 30
    burst_window = 2.0  # seconds

    # Pick a lightweight tool for the test
    test_tool = None
    for tool in tools:
        if tool.get("name") in ("echo", "get_user_info", "internal_tool"):
            test_tool = tool
            break
    if not test_tool and tools:
        test_tool = tools[0]

    if not test_tool:
        return CheckResult(check_id="RATE-001", passed=True)

    tool_name = test_tool["name"]
    # Build minimal valid args
    schema = test_tool.get("inputSchema", {})
    props = schema.get("properties", {})
    test_args = {}
    for prop_name, prop_schema in props.items():
        if prop_schema.get("type") == "string":
            test_args[prop_name] = "rate_limit_test"
        elif prop_schema.get("type") == "integer":
            test_args[prop_name] = 1
        break  # Just need one param

    # Fire burst
    successes = 0
    failures = 0
    start = time.time()

    for i in range(burst_count):
        try:
            client.call_tool(tool_name, test_args)
            successes += 1
        except Exception:
            failures += 1

    elapsed = time.time() - start

    # If all requests succeeded within the burst window, no rate limiting
    if successes == burst_count and elapsed < burst_window * 2:
        rps = successes / elapsed if elapsed > 0 else successes
        findings.append(Finding(
            check_id="RATE-001",
            title="No rate limiting detected",
            severity=Severity.MEDIUM,
            description=(
                f"Sent {burst_count} requests in {elapsed:.1f}s ({rps:.0f} req/s). "
                f"All {successes} succeeded with zero throttling. An attacker can "
                "hammer this server with unlimited requests, enabling denial of service, "
                "brute force attacks, and rapid data extraction."
            ),
            evidence=f"{successes}/{burst_count} requests succeeded in {elapsed:.1f}s",
            tool_name=tool_name,
            remediation=(
                "Implement rate limiting per client IP or per authenticated identity. "
                "Use token bucket or sliding window algorithms. Return HTTP 429 "
                "when the limit is exceeded. Consider per-tool rate limits for "
                "sensitive operations."
            ),
        ))

    return CheckResult(
        check_id="RATE-001",
        passed=len(findings) == 0,
        findings=findings,
    )


def run_rate_limit_checks(client: MCPClient, tools: list) -> list:
    """Run all rate limiting checks. Returns list of CheckResult."""
    return [check_rate_limiting(client, tools)]
