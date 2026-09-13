from dataclasses import dataclass
from pathlib import Path
import os
import shutil

__test__ = False

@dataclass(frozen=True)
class EnvironmentRollbackInput:
    project_root: Path
    baseline_dir: Path
    target_paths: tuple[str, ...]

@dataclass(frozen=True)
class EnvironmentRollbackResult:
    restored: tuple[str, ...]
    missing_baseline: tuple[str, ...]
    failed: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, EnvironmentRollbackInput):
        raise TypeError("INPUT_MUST_BE_ENVIRONMENT_ROLLBACK_INPUT")
    if not isinstance(x.project_root, Path) or not x.project_root.is_dir():
        raise ValueError("PROJECT_ROOT_MUST_BE_EXISTING_DIRECTORY")
    if not isinstance(x.baseline_dir, Path) or not x.baseline_dir.is_dir():
        raise ValueError("BASELINE_DIR_MUST_BE_EXISTING_DIRECTORY")
    if not isinstance(x.target_paths, tuple):
        raise TypeError("TARGET_PATHS_MUST_BE_TUPLE")
    for p in x.target_paths:
        if not isinstance(p, str) or not p or "\x00" in p:
            raise ValueError("INVALID_TARGET_PATH")
        q = Path(p)
        if q.is_absolute() or ".." in q.parts:
            raise ValueError("TARGET_PATH_MUST_BE_RELATIVE")
    return x

def environment_rollback(request):
    x = _validate(request)
    restored, missing, failed = [], [], []

    for rel in sorted(set(x.target_paths)):
        src = x.baseline_dir / rel
        dst = x.project_root / rel
        try:
            if not src.exists() and not src.is_symlink():
                missing.append(rel)
                continue

            if dst.exists() or dst.is_symlink():
                if dst.is_dir() and not dst.is_symlink():
                    shutil.rmtree(dst)
                else:
                    dst.unlink()

            dst.parent.mkdir(parents=True, exist_ok=True)

            if src.is_symlink():
                dst.symlink_to(os.readlink(src))
            elif src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

            restored.append(rel)
        except (OSError, shutil.Error):
            failed.append(rel)

    status = "PASS" if not missing and not failed else "FAIL"
    return EnvironmentRollbackResult(
        tuple(restored),
        tuple(missing),
        tuple(failed),
        status,
    )

environment_rollback.__test__ = False
