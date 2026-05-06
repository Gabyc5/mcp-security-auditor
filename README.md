# MCP Security Auditor

A security scanner for [Model Context Protocol](https://modelcontextprotocol.io/) servers. Probes MCP endpoints for common misconfigurations, injection vulnerabilities, secrets leakage, and transport security issues.

MCP is the open standard AI agents use to connect to external tools. Most implementations ship with no security tooling. This project fills that gap.

## What it checks

| ID | Check | Severity |
|---|---|---|
| AUTH-001 | Unauthenticated access | CRITICAL |
| AUTH-002 | Weak/default credentials | HIGH |
| SCHEMA-001 | Permissive input schemas | MEDIUM |
| SCHEMA-002 | Dangerous parameter types (shell, SQL, paths) | CRITICAL |
| INJECT-001 | Tool description poisoning | CRITICAL |
| INJECT-002 | Response injection | HIGH |
| LEAK-001 | Secrets in tool metadata | CRITICAL |
| LEAK-002 | Verbose error messages | MEDIUM |
| TRANSPORT-001 | No TLS | HIGH |
| TRANSPORT-002 | Wildcard CORS | HIGH |
| RATE-001 | No rate limiting | MEDIUM |

Findings reference real CVEs including CVE-2025-68143, CVE-2025-68145, CVE-2025-49596, and CVE-2026-30615.

## Quick start

### 1. Start the vulnerable test server

```bash
docker compose up -d
```

This runs a deliberately insecure MCP server on `localhost:8080`. Do not expose it to the internet.

### 2. Install the auditor

```bash
pip install -r requirements.txt
```

### 3. Run the scan

```bash
python -m auditor scan http://localhost:8080
```

Save reports:

```bash
python -m auditor scan http://localhost:8080 --output reports/scan.md --json reports/scan.json
```

### 4. Read the report

The Markdown report ranks findings by severity and includes remediation guidance for each issue.

## Project structure

```
├── auditor/                  # The scanner
│   ├── __main__.py           # CLI entry point
│   ├── client.py             # MCP JSON-RPC client
│   ├── scanner.py            # Check orchestrator
│   ├── reporter.py           # Report formatter
│   ├── models.py             # Finding/severity data models
│   └── checks/               # Security check modules
│       ├── auth.py           # Authentication checks
│       ├── schema.py         # Schema validation checks
│       ├── injection.py      # Prompt injection checks
│       ├── leakage.py        # Information leakage checks
│       ├── transport.py      # Transport security checks
│       └── rate_limit.py     # Rate limiting checks
├── vulnerable-server/        # Deliberately insecure MCP server
│   ├── Dockerfile
│   └── server.py
├── docker-compose.yml
├── requirements.txt
├── TECHNICAL_REFERENCE.md    # Deep-dive technical documentation
└── reports/                  # Scan output directory
```

## Vulnerable test server

The included MCP server has intentional security flaws mapped to real CVEs:

| Vulnerability | Tool | Real-world parallel |
|---|---|---|
| Command injection | `run_command` | CVE-2025-68143 (mcp-server-git) |
| Path traversal | `read_file` | CVE-2025-68145 (mcp-server-git) |
| SQL injection | `query_database` | Common in database MCP servers |
| Secrets in metadata | `get_user_info` | Widespread in community servers |
| Tool description poisoning | `internal_tool` | CVE-2026-30615 (Windsurf) |
| Response injection | `echo` | Protocol-level weakness |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No critical or high findings |
| 1 | High-severity findings |
| 2 | Critical-severity findings |

## License

MIT
