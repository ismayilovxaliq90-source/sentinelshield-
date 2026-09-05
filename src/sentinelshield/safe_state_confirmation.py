from __future__ import annotations

from dataclasses import dataclass


class SafeStateError(RuntimeError):
    """Raised when the system cannot be confirmed safe."""


@dataclass(frozen=True)
class SafetyCheck:
    name: str
    passed: bool
    message: str


@dataclass(frozen=True)
class SafeStateReport:
    safe: bool
    checks: tuple[SafetyCheck, ...]


class SafeStateConfirmation:
    """
    Task 39 — Safe-State Confirmation.

    Evaluates already-produced safety checks and confirms whether
    the system is in an acceptable safe state.

    This component does not execute commands, modify files,
    terminate processes, or perform recovery.
    """

    REQUIRED_CHECKS = (
        "workspace",
        "command",
        "arguments",
        "environment",
        "secrets",
        "privilege",
        "process",
        "resources",
        "watchdog",
        "storage",
        "execution",
        "health",
    )

    def __init__(self) -> None:
        self._last_report: SafeStateReport | None = None

    @property
    def report(self) -> SafeStateReport | None:
        return self._last_report

    def confirm(
        self,
        checks: list[SafetyCheck] | tuple[SafetyCheck, ...],
    ) -> SafeStateReport:

        if not isinstance(checks, (list, tuple)):
            raise TypeError(
                "checks must be a list or tuple"
            )

        normalized = tuple(checks)

        names: set[str] = set()

        for check in normalized:
            if not isinstance(check, SafetyCheck):
                raise TypeError(
                    "all checks must be SafetyCheck instances"
                )

            if not check.name.strip():
                raise ValueError(
                    "check name cannot be empty"
                )

            if check.name in names:
                raise ValueError(
                    f"duplicate check: {check.name}"
                )

            names.add(check.name)

        missing = [
            name
            for name in self.REQUIRED_CHECKS
            if name not in names
        ]

        if missing:
            raise SafeStateError(
                "required safety checks are missing: "
                + ", ".join(missing)
            )

        ordered = tuple(
            sorted(
                normalized,
                key=lambda check: check.name,
            )
        )

        safe = all(
            check.passed
            for check in ordered
        )

        report = SafeStateReport(
            safe=safe,
            checks=ordered,
        )

        self._last_report = report

        return report

    def require_safe(
        self,
        checks: list[SafetyCheck] | tuple[SafetyCheck, ...],
    ) -> SafeStateReport:

        report = self.confirm(checks)

        if not report.safe:
            failed = [
                check.name
                for check in report.checks
                if not check.passed
            ]

            raise SafeStateError(
                "safe-state confirmation failed: "
                + ", ".join(failed)
            )

        return report

    def is_safe(
        self,
        checks: list[SafetyCheck] | tuple[SafetyCheck, ...],
    ) -> bool:
        try:
            return self.confirm(checks).safe
        except (SafeStateError, TypeError, ValueError):
            return False
