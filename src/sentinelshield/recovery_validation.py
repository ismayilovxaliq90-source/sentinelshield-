from dataclasses import dataclass
from pathlib import Path

__test__ = False

@dataclass(frozen=True)
class RecoveryValidationInput:
    project_root: Path
    expected_paths: tuple[str, ...]

@dataclass(frozen=True)
class RecoveryValidationResult:
    missing: tuple[str, ...]
    present: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, RecoveryValidationInput):
        raise TypeError("INPUT_MUST_BE_RECOVERY_VALIDATION_INPUT")
    if not isinstance(x.project_root, Path) or not x.project_root.is_dir():
        raise ValueError("PROJECT_ROOT_MUST_BE_EXISTING_DIRECTORY")
    if not isinstance(x.expected_paths, tuple):
        raise TypeError("EXPECTED_PATHS_MUST_BE_TUPLE")
    for p in x.expected_paths:
        if not isinstance(p, str) or not p or "\x00" in p:
            raise ValueError("INVALID_EXPECTED_PATH")
        q = Path(p)
        if q.is_absolute() or ".." in q.parts:
            raise ValueError("EXPECTED_PATH_MUST_BE_RELATIVE")
    return x

def recovery_validation(request):
    x = _validate(request)
    present, missing = [], []
    for rel in sorted(set(x.expected_paths)):
        if (x.project_root / rel).exists():
            present.append(rel)
        else:
            missing.append(rel)
    return RecoveryValidationResult(
        tuple(missing), tuple(present),
        "PASS" if not missing else "FAIL"
    )

recovery_validation.__test__ = False
