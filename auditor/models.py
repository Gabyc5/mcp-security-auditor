"""
Data models for security findings.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = [self.CRITICAL, self.HIGH, self.MEDIUM, self.LOW, self.INFO]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A single security finding from a check."""
    check_id: str          # e.g. "AUTH-001"
    title: str             # Human-readable title
    severity: Severity
    description: str       # What was found
    evidence: str = ""     # Proof (sanitized)
    remediation: str = ""  # How to fix it
    tool_name: str = ""    # Which tool triggered it (if applicable)
    cve_refs: list = field(default_factory=list)  # Related CVEs


@dataclass
class CheckResult:
    """Result of running a check module."""
    check_id: str
    passed: bool
    findings: list = field(default_factory=list)  # List[Finding]
