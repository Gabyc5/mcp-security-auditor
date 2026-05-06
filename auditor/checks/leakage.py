"""
Information leakage checks.

LEAK-001: Secrets exposed in tool metadata (descriptions, schemas)
LEAK-002: Verbose error messages revealing internals
"""

import re
from auditor.models import Finding, CheckResult, Severity
from auditor.client import MCPClient


# Regex patterns for common secret formats
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "API key (sk-* format)"),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}", "API key assignment"),
    (r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{4,}", "Password assignment"),
    (r"(?i)secret\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{16,}", "Secret assignment"),
    (r"(?i)token\s*[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}", "Token assignment"),
    (r"(?i)(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}", "AWS credential"),
    (r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}", "Bearer token"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private key"),
    (r"(?i)(mysql|postgres|mongodb)://[^\s]+", "Database connection string"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"xox[bpsa]-[a-zA-Z0-9-]+", "Slack token"),
]


def check_secrets_in_metadata(tools: list) -> CheckResult:
    """
    LEAK-001: Scan tool metadata for hardcoded secrets.
    
    When an AI agent calls tools/list, the server returns tool names,
    descriptions, and input schemas. All of this text goes into the
    model's context. If secrets are embedded in any of these fields,
    the model (and anyone reading the conversation) can see them.
    """
    findings = []

    for tool in tools:
        tool_name = tool.get("name", "unknown")

        # Scan all text fields in the tool definition
        text_to_scan = {
            "description": tool.get("description", ""),
            "name": tool_name,
        }

        # Also scan schema descriptions
        schema = tool.get("inputSchema", {})
        for prop_name, prop_schema in schema.get("properties", {}).items():
            text_to_scan[f"schema.{prop_name}.description"] = prop_schema.get("description", "")

        for field_name, text in text_to_scan.items():
            if not text:
                continue

            for pattern, label in SECRET_PATTERNS:
                matches = re.findall(pattern, text)
                if matches:
                    # Redact the actual secret in the finding
                    match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    redacted = match_str[:8] + "..." + match_str[-4:] if len(match_str) > 16 else "***REDACTED***"

                    findings.append(Finding(
                        check_id="LEAK-001",
                        title=f"Tool '{tool_name}': {label} in {field_name}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A {label} was found in the tool's {field_name} field. "
                            "This is returned to AI agents via tools/list and will appear "
                            "in the model's context window. Anyone with access to the "
                            "conversation can extract this secret."
                        ),
                        evidence=f"Redacted match: {redacted}",
                        tool_name=tool_name,
                        remediation=(
                            "Remove all secrets from tool metadata. Use environment variables "
                            "or a secrets manager at runtime. Never embed credentials in "
                            "tool descriptions or schemas."
                        ),
                    ))

    return CheckResult(
        check_id="LEAK-001",
        passed=len(findings) == 0,
        findings=findings,
    )


def check_verbose_errors(client: MCPClient, tools: list) -> CheckResult:
    """
    LEAK-002: Test if error responses expose internal information.
    
    Sends deliberately malformed inputs to each tool and checks if the
    error responses contain stack traces, file paths, database schemas,
    connection strings, or other internal details.
    """
    findings = []

    # Error-provoking inputs
    bad_inputs = [
        {"_trigger": "missing_required", "args": {}},
        {"_trigger": "wrong_type", "args": {"*": 99999}},
        {"_trigger": "path_traversal", "args": {"path": "../../../../etc/shadow", "file": "../../../../etc/shadow"}},
        {"_trigger": "sql_error", "args": {"sql": "SELECT * FROM nonexistent_table_xyzzy", "query": "INVALID SQL !!!"}},
    ]

    # Patterns that indicate information leakage in errors
    leak_indicators = [
        (r"Traceback \(most recent call last\)", "Python stack trace", Severity.MEDIUM),
        (r"at .+\.py:\d+", "Python file path with line number", Severity.MEDIUM),
        (r"File \"/.+\"", "Absolute file path", Severity.MEDIUM),
        (r"(?i)(sqlite3|mysql|postgres|mariadb)\.", "Database engine identifier", Severity.LOW),
        (r"(?i)no such table", "Database schema leak", Severity.LOW),
        (r"(?i)connection refused|ECONNREFUSED", "Internal service endpoint leak", Severity.LOW),
        (r"/home/|/root/|/var/|/opt/|/usr/", "Server filesystem path", Severity.MEDIUM),
        (r"(?i)(errno|error code)\s*:?\s*\d+", "System error code", Severity.LOW),
    ]

    for tool in tools:
        tool_name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        for test in bad_inputs:
            # Build args: use test args, mapping '*' to first property
            args = {}
            for key, val in test["args"].items():
                if key == "*":
                    for prop_name in properties:
                        args[prop_name] = val
                        break
                elif key in properties:
                    args[key] = val
                else:
                    # Try to match by common names
                    for prop_name in properties:
                        if key.lower() in prop_name.lower():
                            args[prop_name] = val
                            break

            if not args:
                continue

            try:
                result = client.call_tool(tool_name, args)
                response_text = ""
                for content in result.get("content", []):
                    if content.get("type") == "text":
                        response_text += content.get("text", "")

                for pattern, label, severity in leak_indicators:
                    if re.search(pattern, response_text):
                        findings.append(Finding(
                            check_id="LEAK-002",
                            title=f"Tool '{tool_name}': {label} in error response",
                            severity=severity,
                            description=(
                                f"When given malformed input ({test['_trigger']}), the tool's error "
                                f"response contained a {label}. This exposes internal implementation "
                                "details that help an attacker map the server's architecture."
                            ),
                            evidence=f"Trigger: {test['_trigger']}",
                            tool_name=tool_name,
                            remediation=(
                                "Return generic error messages to clients. Log detailed errors "
                                "server-side only. Never expose stack traces, file paths, or "
                                "database details in MCP tool responses."
                            ),
                        ))
                        break  # One leak per tool per trigger is enough
            except Exception:
                continue

    return CheckResult(
        check_id="LEAK-002",
        passed=len(findings) == 0,
        findings=findings,
    )


def run_leakage_checks(client: MCPClient, tools: list) -> list:
    """Run all leakage checks. Returns list of CheckResult."""
    return [
        check_secrets_in_metadata(tools),
        check_verbose_errors(client, tools),
    ]
