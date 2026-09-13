from dataclasses import dataclass
from pathlib import Path
import subprocess

__test__ = False


@dataclass(frozen=True)
class DatabaseCompatibilityValidationInput:
    project_root: str
    command: tuple[str, ...]
    timeout_seconds: int = 120


@dataclass(frozen=True)
class DatabaseCompatibilityValidationResult:
    command: tuple[str, ...]
    return_code: int
    compatible: bool
    timed_out: bool
    stdout: str
    stderr: str
    status: str


def validate_database_compatibility(
    request: DatabaseCompatibilityValidationInput,
) -> DatabaseCompatibilityValidationResult:
    if not isinstance(request, DatabaseCompatibilityValidationInput):
        raise TypeError(
            "INPUT_MUST_BE_DATABASE_COMPATIBILITY_VALIDATION_INPUT"
        )
    if not isinstance(request.project_root, str) or not request.project_root.strip():
        raise ValueError("PROJECT_ROOT_MUST_BE_NON_EMPTY_STRING")
    if "\x00" in request.project_root:
        raise ValueError("PROJECT_ROOT_CONTAINS_NULL_CHARACTER")
    if not isinstance(request.command, tuple) or not request.command:
        raise TypeError("COMMAND_MUST_BE_NON_EMPTY_TUPLE")
    if any(not isinstance(x, str) or not x for x in request.command):
        raise TypeError("COMMAND_MUST_CONTAIN_NON_EMPTY_STRINGS")
    if isinstance(request.timeout_seconds, bool) or not isinstance(
        request.timeout_seconds, int
    ):
        raise TypeError("TIMEOUT_MUST_BE_INTEGER")
    if request.timeout_seconds <= 0:
        raise ValueError("TIMEOUT_MUST_BE_POSITIVE")

    root = Path(request.project_root).expanduser()
    if not root.exists():
        raise FileNotFoundError("PROJECT_ROOT_NOT_FOUND")
    if not root.is_dir():
        raise NotADirectoryError("PROJECT_ROOT_MUST_BE_DIRECTORY")

    try:
        result = subprocess.run(
            request.command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=request.timeout_seconds,
            check=False,
        )
        return DatabaseCompatibilityValidationResult(
            command=request.command,
            return_code=result.returncode,
            compatible=result.returncode == 0,
            timed_out=False,
            stdout=result.stdout,
            stderr=result.stderr,
            status="PASS" if result.returncode == 0 else "FAIL",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return DatabaseCompatibilityValidationResult(
            command=request.command,
            return_code=-1,
            compatible=False,
            timed_out=True,
            stdout=stdout,
            stderr=stderr,
            status="TIMEOUT",
        )


def database_compatibility_validation(
    request: DatabaseCompatibilityValidationInput,
) -> DatabaseCompatibilityValidationResult:
    return validate_database_compatibility(request)


__all__ = [
    "DatabaseCompatibilityValidationInput",
    "DatabaseCompatibilityValidationResult",
    "validate_database_compatibility",
    "database_compatibility_validation",
]
