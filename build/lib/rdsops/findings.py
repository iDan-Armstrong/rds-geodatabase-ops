"""Findings: the one output shape every rdsops check produces.

A check never prints and never exits. It returns findings; the CLI decides how
to render them and what exit code they add up to. That keeps every check
testable as a plain function.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    OK = 0
    INFO = 1
    WARN = 2
    FAIL = 3


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


def worst(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), default=Severity.OK)


def exit_code(findings: list[Finding]) -> int:
    """0 clean or informational, 1 warnings, 2 failures. Scripts and schedulers key off this."""
    return {Severity.OK: 0, Severity.INFO: 0, Severity.WARN: 1, Severity.FAIL: 2}[worst(findings)]
