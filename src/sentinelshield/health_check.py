from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HealthCheckResult:
    healthy: bool
    checks: dict[str, bool]

    @property
    def passed(self) -> int:
        return sum(self.checks.values())

    @property
    def total(self) -> int:
        return len(self.checks)


class SentinelShieldHealthCheck:
    """
    Lightweight local health verification.

    This check does not execute recovery actions,
    modify projects, or communicate externally.
    """

    def __init__(
        self,
        *,
        project_root: str | Path,
        audit_path: str | Path,
        alert_path: str | Path,
    ):
        self.project_root = Path(project_root)
        self.audit_path = Path(audit_path)
        self.alert_path = Path(alert_path)

    def run(self) -> HealthCheckResult:
        checks = {
            "PROJECT_ROOT": self.project_root.exists(),
            "SRC_PACKAGE": (
                self.project_root
                / "src"
                / "sentinelshield"
            ).is_dir(),
            "TESTS": (
                self.project_root
                / "tests"
            ).is_dir(),
            "AUDIT_PARENT": (
                self.audit_path.parent.exists()
            ),
            "ALERT_PARENT": (
                self.alert_path.parent.exists()
            ),
        }

        return HealthCheckResult(
            healthy=all(checks.values()),
            checks=checks,
        )
