"""
Schema validation checks.

SCHEMA-001: Overly permissive input schemas (missing required fields, no validation)
SCHEMA-002: Dangerous parameter types (shell commands, file paths, raw SQL)
"""

import re
from auditor.models import Finding, CheckResult, Severity


# Patterns that indicate dangerous input types
DANGEROUS_PATTERNS = {
    "shell_command": {
        "keywords": ["command", "cmd", "exec", "shell", "bash", "sh"],
        "desc_keywords": ["execute", "run command", "shell"],
        "severity": Severity.CRITICAL,
        "description": "Tool accepts raw shell commands as input",
        "remediation": (
            "Never accept raw shell commands via MCP tools. Use an allowlist of "
            "permitted operations, or parameterize commands so the user provides "
            "arguments, not the command itself. Reference: CVE-2025-68143."
        ),
        "cves": ["CVE-2025-68143"],
    },
    "file_path": {
        "keywords": ["path", "filepath", "filename", "file_path", "directory"],
        "desc_keywords": ["read file", "file system", "filesystem"],
        "severity": Severity.HIGH,
        "description": "Tool accepts arbitrary file paths without apparent validation",
        "remediation": (
            "Validate all file paths against an allowlist of permitted directories. "
            "Reject paths containing '..' or absolute paths outside the allowed root. "
            "Reference: CVE-2025-68145."
        ),
        "cves": ["CVE-2025-68145"],
    },
    "sql_query": {
        "keywords": ["sql", "query", "statement"],
        "desc_keywords": ["sql query", "database query", "run a sql"],
        "severity": Severity.CRITICAL,
        "description": "Tool accepts raw SQL queries as input",
        "remediation": (
            "Use parameterized queries. If the tool must accept flexible queries, "
            "implement a query parser that validates against an allowlist of "
            "permitted operations (SELECT only, specific tables)."
        ),
        "cves": [],
    },
    "url": {
        "keywords": ["url", "endpoint", "uri"],
        "desc_keywords": ["fetch url", "request url"],
        "severity": Severity.MEDIUM,
        "description": "Tool accepts arbitrary URLs, potential SSRF vector",
        "remediation": (
            "Validate URLs against an allowlist of permitted domains. "
            "Block internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, localhost)."
        ),
        "cves": [],
    },
}


def check_permissive_schemas(tools: list) -> CheckResult:
    """
    SCHEMA-001: Check for overly permissive input schemas.
    
    Looks for:
    - Missing 'required' field (all inputs optional)
    - Missing property-level validation (no enum, pattern, min/max)
    - Accepting 'any' type or missing type constraints
    """
    findings = []

    for tool in tools:
        schema = tool.get("inputSchema", {})
        tool_name = tool.get("name", "unknown")
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # No schema at all
        if not schema or not properties:
            findings.append(Finding(
                check_id="SCHEMA-001",
                title=f"Tool '{tool_name}' has no input schema",
                severity=Severity.MEDIUM,
                description=(
                    "This tool defines no input schema, meaning any input will be accepted. "
                    "An AI agent or attacker can pass arbitrary data."
                ),
                tool_name=tool_name,
                remediation="Define a strict JSON Schema for all tool inputs.",
            ))
            continue

        # No required fields
        if not required:
            findings.append(Finding(
                check_id="SCHEMA-001",
                title=f"Tool '{tool_name}' has no required fields",
                severity=Severity.LOW,
                description=(
                    "The input schema defines properties but none are marked as required. "
                    "The tool may behave unexpectedly with missing inputs."
                ),
                tool_name=tool_name,
                remediation="Mark essential parameters as required in the JSON Schema.",
            ))

        # Check each property for weak validation
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "")

            # String with no constraints
            if prop_type == "string":
                has_validation = any(
                    k in prop_schema for k in ["enum", "pattern", "maxLength", "minLength", "format"]
                )
                if not has_validation:
                    findings.append(Finding(
                        check_id="SCHEMA-001",
                        title=f"Tool '{tool_name}': unconstrained string parameter '{prop_name}'",
                        severity=Severity.LOW,
                        description=(
                            f"Parameter '{prop_name}' accepts any string with no length limits, "
                            "pattern validation, or enumerated values."
                        ),
                        tool_name=tool_name,
                        remediation=(
                            f"Add validation constraints to '{prop_name}': maxLength, "
                            "pattern regex, or an enum of allowed values."
                        ),
                    ))

    return CheckResult(
        check_id="SCHEMA-001",
        passed=len(findings) == 0,
        findings=findings,
    )


def check_dangerous_params(tools: list) -> CheckResult:
    """
    SCHEMA-002: Check for parameters that accept dangerous input types.
    
    Scans tool parameter names and descriptions for patterns that suggest
    the tool accepts shell commands, file paths, SQL queries, or URLs
    without validation.
    """
    findings = []

    for tool in tools:
        schema = tool.get("inputSchema", {})
        tool_name = tool.get("name", "unknown")
        tool_desc = tool.get("description", "").lower()
        properties = schema.get("properties", {})

        for prop_name, prop_schema in properties.items():
            prop_desc = prop_schema.get("description", "").lower()
            prop_name_lower = prop_name.lower()

            for pattern_name, pattern in DANGEROUS_PATTERNS.items():
                # Check parameter name
                name_match = any(kw in prop_name_lower for kw in pattern["keywords"])
                # Check parameter description
                desc_match = any(kw in prop_desc for kw in pattern["desc_keywords"])
                # Check tool description
                tool_desc_match = any(kw in tool_desc for kw in pattern["desc_keywords"])

                if name_match or desc_match or tool_desc_match:
                    # Check if there's any validation that might mitigate
                    has_mitigation = any(
                        k in prop_schema for k in ["enum", "pattern", "maxLength"]
                    )
                    if not has_mitigation:
                        findings.append(Finding(
                            check_id="SCHEMA-002",
                            title=f"Tool '{tool_name}': dangerous parameter '{prop_name}' ({pattern_name})",
                            severity=pattern["severity"],
                            description=pattern["description"],
                            evidence=f"Parameter '{prop_name}' in tool '{tool_name}'",
                            tool_name=tool_name,
                            remediation=pattern["remediation"],
                            cve_refs=pattern["cves"],
                        ))
                        break  # One match per property is enough

    return CheckResult(
        check_id="SCHEMA-002",
        passed=len(findings) == 0,
        findings=findings,
    )


def run_schema_checks(tools: list) -> list:
    """Run all schema checks. Returns list of CheckResult."""
    return [
        check_permissive_schemas(tools),
        check_dangerous_params(tools),
    ]
