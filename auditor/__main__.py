"""
MCP Security Auditor — CLI entry point.

Usage:
    python -m auditor scan <target_url> [--output report.md] [--json report.json]

Example:
    python -m auditor scan http://localhost:8080
    python -m auditor scan http://localhost:8080 --output reports/scan.md --json reports/scan.json
"""

import sys
import os
from auditor.scanner import scan
from auditor.reporter import generate_markdown, generate_json


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "scan":
        print("MCP Security Auditor")
        print("")
        print("Usage: python -m auditor scan <target_url> [--output report.md] [--json report.json]")
        print("")
        print("Example:")
        print("  python -m auditor scan http://localhost:8080")
        print("  python -m auditor scan http://localhost:8080 --output reports/scan.md")
        sys.exit(1)

    target_url = sys.argv[2]
    md_output = None
    json_output = None

    # Parse optional flags
    args = sys.argv[3:]
    for i, arg in enumerate(args):
        if arg == "--output" and i + 1 < len(args):
            md_output = args[i + 1]
        elif arg == "--json" and i + 1 < len(args):
            json_output = args[i + 1]

    # Run scan
    print("=" * 60)
    print("  MCP SECURITY AUDITOR")
    print("=" * 60)

    result = scan(target_url)

    if "error" in result:
        print(f"\n[!] Scan failed: {result['error']}")
        sys.exit(1)

    # Generate reports
    md_report = generate_markdown(result)

    # Output Markdown
    if md_output:
        os.makedirs(os.path.dirname(md_output) or ".", exist_ok=True)
        with open(md_output, "w") as f:
            f.write(md_report)
        print(f"\n[+] Markdown report saved to {md_output}")
    else:
        print("\n" + md_report)

    # Output JSON
    if json_output:
        os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
        json_report = generate_json(result)
        with open(json_output, "w") as f:
            f.write(json_report)
        print(f"[+] JSON report saved to {json_output}")

    # Exit code based on severity
    summary = result.get("summary", {})
    if summary.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif summary.get("HIGH", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
