from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class PythonVirtualEnvironmentValidationError(ValueError):
    """Raised for invalid Python virtual-environment validation input."""


@dataclass(frozen=True)
class PythonVirtualEnvironmentValidationInput:
    environment_path: str | Path | None = None
    require_virtual_environment: bool = True


@dataclass(frozen=True)
class PythonVirtualEnvironmentValidationResult:
    valid: bool
    status: str
    environment_path: str
    environment_exists: bool
    pyvenv_cfg_exists: bool
    python_executable: str
    python_executable_exists: bool
    interpreter_prefix: str
    base_prefix: str
    interpreter_is_virtual_environment: bool
    python_version: str
    platform: str
    reasons: tuple[str, ...]
    errors: tuple[str, ...]


def _validate_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name}_MUST_BE_BOOL")
    return value


def _resolve_environment_path(
    requested: str | Path | None,
) -> Path:
    if requested is not None:
        if not isinstance(requested, (str, Path)):
            raise TypeError("ENVIRONMENT_PATH_MUST_BE_STRING_OR_PATH")

        text = str(requested).strip()
        if not text:
            raise ValueError("ENVIRONMENT_PATH_IS_EMPTY")

        return Path(text).expanduser().resolve()

    for variable in (
        "VIRTUAL_ENV",
        "SENTINELSHIELD_VENV",
    ):
        value = os.getenv(variable, "").strip()
        if value:
            return Path(value).expanduser().resolve()

    return Path.cwd().resolve() / ".venv"


def _python_executable(environment: Path) -> Path:
    if platform.system().casefold() == "windows":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _read_python_version(executable: Path) -> str:
    if not executable.is_file():
        return ""

    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (
        OSError,
        subprocess.SubprocessError,
    ):
        return ""

    output = (completed.stdout or completed.stderr).strip()
    return output.removeprefix("Python ").strip()


def validate_python_virtual_environment(
    request: PythonVirtualEnvironmentValidationInput | None = None,
) -> PythonVirtualEnvironmentValidationResult:
    if request is None:
        request = PythonVirtualEnvironmentValidationInput()

    if not isinstance(
        request,
        PythonVirtualEnvironmentValidationInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_PYTHON_VIRTUAL_ENVIRONMENT_VALIDATION_INPUT"
        )

    require_virtual_environment = _validate_bool(
        request.require_virtual_environment,
        "REQUIRE_VIRTUAL_ENVIRONMENT",
    )

    environment = _resolve_environment_path(
        request.environment_path
    )

    environment_exists = environment.exists()
    pyvenv_cfg = environment / "pyvenv.cfg"
    pyvenv_cfg_exists = pyvenv_cfg.is_file()

    executable = _python_executable(environment)
    executable_exists = executable.is_file()

    reasons: list[str] = []
    errors: list[str] = []

    if environment_exists and environment.is_dir():
        reasons.append("VIRTUAL_ENVIRONMENT_DIRECTORY_EXISTS")
    else:
        errors.append("VIRTUAL_ENVIRONMENT_DIRECTORY_MISSING")

    if pyvenv_cfg_exists:
        reasons.append("PYVENV_CFG_PRESENT")
    else:
        errors.append("PYVENV_CFG_MISSING")

    if executable_exists:
        reasons.append("PYTHON_EXECUTABLE_PRESENT")
    else:
        errors.append("PYTHON_EXECUTABLE_MISSING")

    interpreter_prefix = str(
        Path(sys.prefix).resolve()
    )
    base_prefix = str(
        Path(sys.base_prefix).resolve()
    )

    interpreter_is_virtual_environment = (
        sys.prefix != sys.base_prefix
    )

    # The current process is informative only. The authoritative
    # interpreter check below is performed by the candidate venv.
    python_version = _read_python_version(executable)

    if executable_exists and python_version:
        reasons.append("PYTHON_VERSION_DETECTED")
    elif executable_exists:
        errors.append("PYTHON_VERSION_UNAVAILABLE")

    if require_virtual_environment:
        if pyvenv_cfg_exists and executable_exists:
            reasons.append("PYTHON_VIRTUAL_ENVIRONMENT_VALID")
        else:
            errors.append("PYTHON_VIRTUAL_ENVIRONMENT_INVALID")

    valid = not errors
    status = "PASS" if valid else "FAIL"

    return PythonVirtualEnvironmentValidationResult(
        valid=valid,
        status=status,
        environment_path=str(environment),
        environment_exists=environment_exists,
        pyvenv_cfg_exists=pyvenv_cfg_exists,
        python_executable=str(executable),
        python_executable_exists=executable_exists,
        interpreter_prefix=interpreter_prefix,
        base_prefix=base_prefix,
        interpreter_is_virtual_environment=(
            interpreter_is_virtual_environment
        ),
        python_version=python_version,
        platform=platform.platform(),
        reasons=tuple(reasons),
        errors=tuple(errors),
    )


def python_virtual_environment_validation(
    request: PythonVirtualEnvironmentValidationInput | None = None,
) -> PythonVirtualEnvironmentValidationResult:
    return validate_python_virtual_environment(request)


def write_validation_evidence(
    result: PythonVirtualEnvironmentValidationResult,
    output_path: str | Path,
) -> Path:
    if not isinstance(
        result,
        PythonVirtualEnvironmentValidationResult,
    ):
        raise TypeError(
            "RESULT_MUST_BE_PYTHON_VIRTUAL_ENVIRONMENT_VALIDATION_RESULT"
        )

    if not isinstance(output_path, (str, Path)):
        raise TypeError("OUTPUT_PATH_MUST_BE_STRING_OR_PATH")

    if not str(output_path).strip():
        raise ValueError("OUTPUT_PATH_IS_EMPTY")

    path = Path(output_path)
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
    "PythonVirtualEnvironmentValidationError",
    "PythonVirtualEnvironmentValidationInput",
    "PythonVirtualEnvironmentValidationResult",
    "validate_python_virtual_environment",
    "python_virtual_environment_validation",
    "write_validation_evidence",
]
