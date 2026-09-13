from dataclasses import dataclass

__test__ = False
_VALID = {"PASS", "FAIL", "TIMEOUT", "ERROR"}
_RECOVERABLE = {"MISSING", "CONFLICT", "VERSION", "SOURCE", "LOCKFILE"}
_KEYWORDS = {
    "MISSING": ("not found", "missing", "no matching distribution", "cannot find"),
    "CONFLICT": ("conflict", "incompatible", "dependency conflict"),
    "VERSION": ("version", "requires", "specifier", "constraint"),
    "SOURCE": ("source", "repository", "registry", "index", "package not found"),
    "LOCKFILE": ("lockfile", "lock file", "lock-file"),
}

@dataclass(frozen=True)
class DependencyResolutionFailureHandlingInput:
    status: str
    message: str = ""
    package: str = ""

@dataclass(frozen=True)
class DependencyResolutionFailureHandlingResult:
    category: str
    recoverable: bool
    package: str
    status: str

def _validate(x):
    if not isinstance(x, DependencyResolutionFailureHandlingInput):
        raise TypeError("INPUT_MUST_BE_DEPENDENCY_RESOLUTION_FAILURE_HANDLING_INPUT")
    for name in ("status", "message", "package"):
        v = getattr(x, name)
        if not isinstance(v, str):
            raise TypeError(f"{name.upper()}_MUST_BE_STRING")
        if "\x00" in v or any(ord(c) < 32 and c not in "\t\n\r" for c in v):
            raise ValueError(f"{name.upper()}_CONTAINS_CONTROL_CHARACTER")
    if not x.status.strip():
        raise ValueError("STATUS_MUST_NOT_BE_EMPTY")
    return x

def handle_dependency_resolution_failure(request):
    r = _validate(request)
    status = r.status.strip().upper()
    msg = r.message.strip().lower()

    category = "UNKNOWN"
    if status == "TIMEOUT":
        category = "TIMEOUT"
    elif status in {"FAIL", "ERROR"}:
        for cat, words in _KEYWORDS.items():
            if any(w in msg for w in words):
                category = cat
                break

    return DependencyResolutionFailureHandlingResult(
        category=category,
        recoverable=category in _RECOVERABLE,
        package=r.package.strip(),
        status="PASS",
    )

def dependency_resolution_failure_handling(request):
    return handle_dependency_resolution_failure(request)

dependency_resolution_failure_handling.__test__ = False
