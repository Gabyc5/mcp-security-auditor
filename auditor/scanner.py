"""
Scanner orchestrator.

Connects to the target MCP server, discovers tools, and runs all
security check modules in sequence.
"""

from auditor.client import MCPClient
from auditor.checks.auth import run_auth_checks
from auditor.checks.schema import run_schema_checks
from auditor.checks.injection import run_injection_checks
from auditor.checks.leakage import run_leakage_checks
from auditor.checks.transport import run_transport_checks
from auditor.checks.rate_limit import run_rate_limit_checks


def scan(target_url: str) -> dict:
    """
    Run the full security audit against a target MCP server.
    
    Returns a dict with:
    - server_info: target server metadata
    - tools: list of discovered tools
    - results: list of CheckResult objects
    - summary: counts by severity
    """
    client = MCPClient(base_url=target_url)

    print(f"\n[*] Connecting to {target_url}")

    # Phase 1: Connect and discover
    try:
        init_result = client.initialize()
        server_info = init_result.get("serverInfo", {})
        print(f"[+] Connected: {server_info.get('name', 'unknown')} v{server_info.get('version', '?')}")
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return {"error": str(e)}

    try:
        tools = client.list_tools()
        print(f"[+] Discovered {len(tools)} tools: {', '.join(t['name'] for t in tools)}")
    except Exception as e:
        print(f"[-] Failed to list tools: {e}")
        tools = []

    # Phase 2: Run checks
    all_results = []

    print("\n[*] Running authentication checks...")
    all_results.extend(run_auth_checks(client, tools))

    print("[*] Running schema validation checks...")
    all_results.extend(run_schema_checks(tools))

    print("[*] Running injection checks...")
    all_results.extend(run_injection_checks(client, tools))

    print("[*] Running leakage checks...")
    all_results.extend(run_leakage_checks(client, tools))

    print("[*] Running transport checks...")
    all_results.extend(run_transport_checks(client))

    print("[*] Running rate limiting checks...")
    all_results.extend(run_rate_limit_checks(client, tools))

    # Phase 3: Summarize
    all_findings = []
    for result in all_results:
        all_findings.extend(result.findings)

    # Sort by severity
    all_findings.sort(key=lambda f: f.severity)

    summary = {
        "CRITICAL": sum(1 for f in all_findings if f.severity.value == "CRITICAL"),
        "HIGH": sum(1 for f in all_findings if f.severity.value == "HIGH"),
        "MEDIUM": sum(1 for f in all_findings if f.severity.value == "MEDIUM"),
        "LOW": sum(1 for f in all_findings if f.severity.value == "LOW"),
        "INFO": sum(1 for f in all_findings if f.severity.value == "INFO"),
        "total": len(all_findings),
    }

    passed = sum(1 for r in all_results if r.passed)
    failed = len(all_results) - passed

    print(f"\n[*] Scan complete: {summary['total']} findings")
    print(f"    CRITICAL: {summary['CRITICAL']}  HIGH: {summary['HIGH']}  "
          f"MEDIUM: {summary['MEDIUM']}  LOW: {summary['LOW']}")
    print(f"    Checks passed: {passed}/{len(all_results)}")

    return {
        "server_info": server_info,
        "tools": tools,
        "results": all_results,
        "findings": all_findings,
        "summary": summary,
        "checks_passed": passed,
        "checks_total": len(all_results),
    }
