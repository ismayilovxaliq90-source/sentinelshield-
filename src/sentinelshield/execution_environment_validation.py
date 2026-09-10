from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class ExecutionEnvironmentValidationError(ValueError):
    """Raised when execution-environment validation cannot be completed safely."""


@dataclass(frozen=True)
class ExecutionEnvironmentValidationInput:
    require_ci: bool = True
    require_github_actions: bool = True
    minimum_free_disk_bytes: int = 100 * 1024 * 1024


@dataclass(frozen=True)
class ExecutionEnvironmentValidationResult:
    valid: bool
    status: str
    environment: str
    ci_detected: bool
    github_actions_detected: bool
    operating_system: str
    architecture: str
    python_version: str
    hostname: str
    workspace: str
    workspace_exists: bool
    workspace_directory: bool
    workspace_writable: bool
    free_disk_bytes: int
    minimum_free_disk_bytes: int
    reasons: tuple[str, ...]
    errors: tuple[str, ...]


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name}_MUST_BE_BOOL")
    return value


def _require_non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name}_MUST_BE_NON_NEGATIVE_INT")
    if value < 0:
        raise ValueError(f"{name}_MUST_BE_NON_NEGATIVE_INT")
    return value


def _detect_ci() -> bool:
    ci_value = os.getenv("CI", "").strip().casefold()
    github_value = os.getenv("GITHUB_ACTIONS", "").strip().casefold()

    return ci_value == "true" or github_value == "true"


def _detect_github_actions() -> bool:
    return os.getenv("GITHUB_ACTIONS", "").strip().casefold() == "true"


def _detect_workspace() -> Path:
    candidates = (
        os.getenv("GITHUB_WORKSPACE", "").strip(),
        os.getenv("RUNNER_WORKSPACE", "").strip(),
        os.getcwd(),
    )

    for candidate in candidates:
        if candidate:
            return Path(candidate).resolve()

    return Path.cwd().resolve()


def _safe_writable_check(path: Path) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _free_disk_bytes(path: Path) -> int:
    try:
        return int(shutil.disk_usage(path).free)
    except OSError as exc:
        raise ExecutionEnvironmentValidationError(
            "DISK_USAGE_CHECK_FAILED"
        ) from exc


def validate_execution_environment(
    request: ExecutionEnvironmentValidationInput | None = None,
) -> ExecutionEnvironmentValidationResult:
    if request is None:
        request = ExecutionEnvironmentValidationInput()

    if not isinstance(request, ExecutionEnvironmentValidationInput):
        raise TypeError("INPUT_MUST_BE_EXECUTION_ENVIRONMENT_VALIDATION_INPUT")

    require_ci = _require_bool(request.require_ci, "REQUIRE_CI")
    require_github_actions = _require_bool(
        request.require_github_actions,
        "REQUIRE_GITHUB_ACTIONS",
    )
    minimum_free_disk_bytes = _require_non_negative_int(
        request.minimum_free_disk_bytes,
        "MINIMUM_FREE_DISK_BYTES",
    )

    ci_detected = _detect_ci()
    github_actions_detected = _detect_github_actions()

    operating_system = platform.system()
    architecture = platform.machine()
    python_version = platform.python_version()
    hostname = socket.gethostname()

    workspace = _detect_workspace()

    workspace_exists = workspace.exists()
    workspace_directory = workspace.is_dir() if workspace_exists else False
    workspace_writable = (
        _safe_writable_check(workspace)
        if workspace_directory
        else False
    )

    disk_path = workspace if workspace_directory else Path.cwd()
    free_disk_bytes = _free_disk_bytes(disk_path)

    reasons: list[str] = []
    errors: list[str] = []

    environment = "SERVER_CI"

    if require_ci:
        if ci_detected:
            reasons.append("CI_ENVIRONMENT_DETECTED")
        else:
            errors.append("CI_ENVIRONMENT_REQUIRED")

    if require_github_actions:
        if github_actions_detected:
            reasons.append("GITHUB_ACTIONS_ENVIRONMENT_DETECTED")
        else:
            errors.append("GITHUB_ACTIONS_ENVIRONMENT_REQUIRED")

    if workspace_exists and workspace_directory:
        reasons.append("WORKSPACE_DIRECTORY_VALID")
    else:
        errors.append("WORKSPACE_DIRECTORY_INVALID")

    if workspace_writable:
        reasons.append("WORKSPACE_WRITABLE")
    else:
        errors.append("WORKSPACE_NOT_WRITABLE")

    if free_disk_bytes >= minimum_free_disk_bytes:
        reasons.append("MINIMUM_FREE_DISK_AVAILABLE")
    else:
        errors.append("INSUFFICIENT_FREE_DISK")

    if operating_system:
        reasons.append("OPERATING_SYSTEM_DETECTED")

    if architecture:
        reasons.append("ARCHITECTURE_DETECTED")

    if python_version:
        reasons.append("PYTHON_RUNTIME_DETECTED")

    valid = not errors
    status = "PASS" if valid else "FAIL"

    return ExecutionEnvironmentValidationResult(
        valid=valid,
        status=status,
        environment=environment,
        ci_detected=ci_detected,
        github_actions_detected=github_actions_detected,
        operating_system=operating_system,
        architecture=architecture,
        python_version=python_version,
        hostname=hostname,
        workspace=str(workspace),
        workspace_exists=workspace_exists,
        workspace_directory=workspace_directory,
        workspace_writable=workspace_writable,
        free_disk_bytes=free_disk_bytes,
        minimum_free_disk_bytes=minimum_free_disk_bytes,
        reasons=tuple(reasons),
        errors=tuple(errors),
    )


def execution_environment_validation(
    request: ExecutionEnvironmentValidationInput | None = None,
) -> ExecutionEnvironmentValidationResult:
    return validate_execution_environment(request)


def write_validation_evidence(
    result: ExecutionEnvironmentValidationResult,
    output_path: str | Path,
) -> Path:
    if not isinstance(result, ExecutionEnvironmentValidationResult):
        raise TypeError("RESULT_MUST_BE_EXECUTION_ENVIRONMENT_VALIDATION_RESULT")

    if not isinstance(output_path, (str, Path)):
        raise TypeError("OUTPUT_PATH_MUST_BE_STRING_OR_PATH")

    path = Path(output_path)

    if not str(path).strip():
        raise ValueError("OUTPUT_PATH_IS_EMPTY")

    path.parent.mkdir(parents=True, exist_ok=True)

    payload = asdict(result)
    payload["reasons"] = list(result.reasons)
    payload["errors"] = list(result.errors)

    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return path


__all__ = [
    "ExecutionEnvironmentValidationError",
    "ExecutionEnvironmentValidationInput",
    "ExecutionEnvironmentValidationResult",
    "validate_execution_environment",
    "execution_environment_validation",
    "write_validation_evidence",
]
