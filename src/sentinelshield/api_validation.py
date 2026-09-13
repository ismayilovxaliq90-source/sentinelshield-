from dataclasses import dataclass
from pathlib import Path
import subprocess

__test__ = False


@dataclass(frozen=True)
class APIValidationInput:
    project_root: str
    command: tuple[str, ...]
    timeout_seconds: int = 120


@dataclass(frozen=True)
class APIValidationResult:
    command: tuple[str, ...]
    return_code: int
    passed: bool
    timed_out: bool
    stdout: str
    stderr: str
    status: str


def validate_api(request: APIValidationInput) -> APIValidationResult:
    if not isinstance(request, APIValidationInput):
        raise TypeError("INPUT_MUST_BE_API_VALIDATION_INPUT")
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
        return APIValidationResult(
            command=request.command,
            return_code=result.returncode,
            passed=result.returncode == 0,
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
        return APIValidationResult(
            command=request.command,
            return_code=-1,
            passed=False,
            timed_out=True,
            stdout=stdout,
            stderr=stderr,
            status="TIMEOUT",
        )


def api_validation(request: APIValidationInput) -> APIValidationResult:
    return validate_api(request)


__all__ = [
    "APIValidationInput",
    "APIValidationResult",
    "validate_api",
    "api_validation",
]
