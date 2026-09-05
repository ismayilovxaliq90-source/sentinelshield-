from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module


class CoreAcceptanceError(RuntimeError):
    """Raised when Minimum Safe Core acceptance fails."""


@dataclass(frozen=True)
class CoreCheck:
    task: int
    name: str
    passed: bool
    message: str


@dataclass(frozen=True)
class CoreAcceptanceReport:
    accepted: bool
    checks: tuple[CoreCheck, ...]


class MinimumCoreAcceptance:
    """
    Task 40 — Minimum Safe Core Acceptance Test.

    Performs non-destructive structural acceptance checks.
    """

    COMPONENTS = (
        (5, "Workspace Isolation", "workspace", "Workspace"),
        (6, "Project Path Validator", "project_path", "ProjectPathValidator"),
        (7, "Command Validator", "command_validator", "CommandValidator"),
        (8, "Argument Validator", "argument_validator", "ArgumentValidator"),
        (
            9,
            "Environment Variable Validator",
            "environment_validator",
            "EnvironmentVariableValidator",
        ),
        (10, "Secret Exposure Guard", "secret_guard", "SecretExposureGuard"),
        (11, "Least Privilege Controller", "least_privilege", "LeastPrivilegeController"),
        (12, "Process Monitor", "process_monitor", "ProcessMonitor"),
        (13, "CPU Monitor", "cpu_monitor", "CPUMonitor"),
        (23, "Watchdog", "watchdog", "Watchdog"),
        (24, "Process Limit", "process_limit", "ProcessLimit"),
        (
            25,
            "Disk / Log Runaway Protection",
            "disk_log_protection",
            "DiskLogRunawayProtection",
        ),
        (26, "Safe Command Execution", "safe_command", "SafeCommandExecutor"),
        (27, "Execution State Tracking", "execution_state", "ExecutionStateTracker"),
        (28, "Emergency Stop", "emergency_stop", "EmergencyStop"),
        (29, "Failure Detection", "failure_detection", "FailureDetection"),
        (
            30,
            "Failure Classification",
            "failure_classification",
            "FailureClassifier",
        ),
        (31, "Baseline Snapshot", "baseline_snapshot", "BaselineSnapshot"),
        (32, "Rollback Controller", "rollback_controller", "RollbackController"),
        (33, "Recovery Controller", "recovery_controller", "RecoveryController"),
        (34, "Cleanup Controller", "cleanup_controller", "CleanupController"),
        (
            35,
            "Deterministic Validation",
            "deterministic_validation",
            "DeterministicValidator",
        ),
        (36, "Final Health Check", "final_health_check", "FinalHealthCheck"),
        (37, "Execution Audit", "execution_audit", "ExecutionAudit"),
        (38, "Evidence Collection", "evidence_collection", "EvidenceCollector"),
        (
            39,
            "Safe-State Confirmation",
            "safe_state_confirmation",
            "SafeStateConfirmation",
        ),
    )

    def check(self) -> CoreAcceptanceReport:
        checks: list[CoreCheck] = []

        for task, name, module_name, class_name in self.COMPONENTS:
            try:
                module = import_module(
                    f"sentinelshield.{module_name}"
                )
            except Exception as exc:
                checks.append(
                    CoreCheck(
                        task=task,
                        name=name,
                        passed=False,
                        message=(
                            f"import failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )
                )
                continue

            if not hasattr(module, class_name):
                checks.append(
                    CoreCheck(
                        task=task,
                        name=name,
                        passed=False,
                        message=(
                            f"missing component: {class_name}"
                        ),
                    )
                )
                continue

            checks.append(
                CoreCheck(
                    task=task,
                    name=name,
                    passed=True,
                    message="OK",
                )
            )

        accepted = all(
            check.passed
            for check in checks
        )

        return CoreAcceptanceReport(
            accepted=accepted,
            checks=tuple(checks),
        )

    def require_accepted(self) -> CoreAcceptanceReport:
        report = self.check()

        if not report.accepted:
            failed = [
                f"TASK {check.task}: {check.name}"
                for check in report.checks
                if not check.passed
            ]

            raise CoreAcceptanceError(
                "Minimum Core acceptance failed: "
                + ", ".join(failed)
            )

        return report
