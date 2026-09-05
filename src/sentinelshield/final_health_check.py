from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module


class HealthCheckError(RuntimeError):
    """Raised when the SentinelShield health check fails."""


@dataclass(frozen=True)
class ComponentHealth:
    name: str
    healthy: bool
    message: str


@dataclass(frozen=True)
class HealthReport:
    healthy: bool
    components: tuple[ComponentHealth, ...]


class FinalHealthCheck:
    """
    Task 36 — Final Health Check.

    Verifies that required SentinelShield Core modules can be imported
    and that the required public components exist.

    This checker does not execute commands, modify files, or terminate
    processes.
    """

    REQUIRED_COMPONENTS = {
        "command_validator": (
            "CommandValidator",
            "CommandValidationError",
        ),
        "argument_validator": (
            "ArgumentValidator",
            "ArgumentValidationError",
        ),
        "environment_validator": (
            "EnvironmentVariableValidator",
            "EnvironmentVariableValidationError",
        ),
        "secret_guard": (
            "SecretExposureGuard",
            "SecretExposureError",
        ),
        "least_privilege": (
            "LeastPrivilegeController",
            "PrivilegeViolation",
        ),
        "process_monitor": (
            "ProcessMonitor",
            "ProcessMonitorError",
        ),
        "cpu_monitor": (
            "CPUMonitor",
            "CPUMonitorError",
        ),
        "watchdog": (
            "Watchdog",
            "WatchdogError",
        ),
        "process_limit": (
            "ProcessLimit",
            "ProcessLimitError",
        ),
        "disk_log_protection": (
            "DiskLogRunawayProtection",
            "DiskLogProtectionError",
        ),
        "safe_command": (
            "SafeCommandExecutor",
            "SafeCommandError",
        ),
        "execution_state": (
            "ExecutionStateTracker",
            "ExecutionStateError",
        ),
        "emergency_stop": (
            "EmergencyStop",
            "EmergencyStopError",
        ),
        "failure_detection": (
            "FailureDetection",
            "FailureEvent",
        ),
        "failure_classification": (
            "FailureClassifier",
            "ClassificationResult",
        ),
        "baseline_snapshot": (
            "BaselineSnapshot",
        ),
        "rollback_controller": (
            "RollbackController",
            "RollbackError",
        ),
        "recovery_controller": (
            "RecoveryController",
            "RecoveryError",
        ),
        "cleanup_controller": (
            "CleanupController",
            "CleanupError",
        ),
        "deterministic_validation": (
            "DeterministicValidator",
            "DeterministicValidationError",
        ),
    }

    def __init__(self) -> None:
        self._report: HealthReport | None = None

    @property
    def report(self) -> HealthReport | None:
        return self._report

    def check(self) -> HealthReport:
        results: list[ComponentHealth] = []

        for module_name, required_names in sorted(
            self.REQUIRED_COMPONENTS.items()
        ):
            full_name = (
                f"sentinelshield.{module_name}"
            )

            try:
                module = import_module(full_name)

                missing = [
                    name
                    for name in required_names
                    if not hasattr(module, name)
                ]

                if missing:
                    results.append(
                        ComponentHealth(
                            name=module_name,
                            healthy=False,
                            message=(
                                "missing components: "
                                + ", ".join(missing)
                            ),
                        )
                    )
                    continue

                results.append(
                    ComponentHealth(
                        name=module_name,
                        healthy=True,
                        message="OK",
                    )
                )

            except Exception as exc:
                results.append(
                    ComponentHealth(
                        name=module_name,
                        healthy=False,
                        message=f"{type(exc).__name__}: {exc}",
                    )
                )

        overall = all(
            component.healthy
            for component in results
        )

        self._report = HealthReport(
            healthy=overall,
            components=tuple(results),
        )

        return self._report

    def require_healthy(self) -> HealthReport:
        report = self.check()

        if not report.healthy:
            unhealthy = [
                component.name
                for component in report.components
                if not component.healthy
            ]

            raise HealthCheckError(
                "Core health check failed: "
                + ", ".join(unhealthy)
            )

        return report
