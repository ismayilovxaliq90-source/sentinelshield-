from dataclasses import dataclass
from pathlib import Path
import subprocess

__test__ = False

@dataclass(frozen=True)
class PackagingValidationInput:
    project_root: Path
    command: tuple[str, ...]
    timeout: int = 600

@dataclass(frozen=True)
class PackagingValidationResult:
    command: tuple[str, ...]
    return_code: int | None
    success: bool
    timed_out: bool
    stdout: str
    stderr: str
    status: str

def validate_packaging(request):
    if not isinstance(request, PackagingValidationInput):
        raise TypeError("INPUT_MUST_BE_PACKAGING_VALIDATION_INPUT")
    if not isinstance(request.project_root, Path) or not request.project_root.is_dir():
        raise ValueError("PROJECT_ROOT_MUST_BE_EXISTING_DIRECTORY")
    if not isinstance(request.command, tuple) or not request.command:
        raise TypeError("COMMAND_MUST_BE_NON_EMPTY_TUPLE")
    if any(not isinstance(x, str) or not x.strip() for x in request.command):
        raise TypeError("COMMAND_ITEMS_MUST_BE_NON_EMPTY_STRINGS")
    if not isinstance(request.timeout, int) or isinstance(request.timeout, bool) or request.timeout <= 0:
        raise ValueError("TIMEOUT_MUST_BE_POSITIVE_INTEGER")
    try:
        p = subprocess.run(request.command,cwd=request.project_root,
                           capture_output=True,text=True,timeout=request.timeout)
        return PackagingValidationResult(
            request.command,p.returncode,p.returncode == 0,False,
            p.stdout,p.stderr,"PASS" if p.returncode == 0 else "FAIL")
    except subprocess.TimeoutExpired as e:
        return PackagingValidationResult(
            request.command,None,False,True,
            e.stdout or "",e.stderr or "","TIMEOUT")

def packaging_validation(request):
    return validate_packaging(request)
