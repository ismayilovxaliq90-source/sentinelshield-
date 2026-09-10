from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class DependencyTreeRegenerationError(RuntimeError):
    """Raised when dependency-tree regeneration cannot be completed safely."""


SUPPORTED_MANAGERS = frozenset(
    {
        "npm",
        "pnpm",
        "yarn",
        "go",
        "cargo",
        "composer",
        "poetry",
    }
)

TREE_COMMANDS = {
    "npm": ("npm", "ls", "--all", "--json", "--package-lock-only"),
    "pnpm": ("pnpm", "list", "--depth", "Infinity", "--json"),
    "yarn": ("yarn", "list", "--json"),
    "go": ("go", "mod", "graph"),
    "cargo": ("cargo", "tree"),
    "composer": ("composer", "show", "--tree"),
    "poetry": ("poetry", "show", "--tree"),
}

MANIFESTS = {
    "npm": ("package.json",),
    "pnpm": ("package.json",),
    "yarn": ("package.json",),
    "go": ("go.mod",),
    "cargo": ("Cargo.toml",),
    "composer": ("composer.json",),
    "poetry": ("pyproject.toml",),
}


@dataclass(frozen=True)
class DependencyTreeFingerprint:
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class DependencyTreeRequest:
    repository_root: Path
    manager: str
    timeout: float = 60.0
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class DependencyTreeResult:
    success: bool
    manager: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    tree: object | None
    fingerprint: DependencyTreeFingerprint | None
    error: str | None

    def to_dict(self) -> dict:
        fingerprint = None
        if self.fingerprint is not None:
            fingerprint = {
                "path": str(self.fingerprint.path),
                "sha256": self.fingerprint.sha256,
                "size": self.fingerprint.size,
            }

        return {
            "success": self.success,
            "manager": self.manager,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "tree": self.tree,
            "fingerprint": fingerprint,
            "error": self.error,
        }


def _repository_root(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencyTreeRegenerationError(
            f"Unable to resolve repository root: {path}"
        ) from exc

    if not root.is_dir():
        raise DependencyTreeRegenerationError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise DependencyTreeRegenerationError(
            f"Not a Git repository: {root}"
        )

    return root


def _validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise DependencyTreeRegenerationError("Invalid timeout")

    if timeout <= 0 or timeout > 900:
        raise DependencyTreeRegenerationError(
            "Timeout must be greater than 0 and at most 900 seconds"
        )


def _manifest_for(manager: str) -> Path:
    try:
        return Path(MANIFESTS[manager][0])
    except KeyError as exc:
        raise DependencyTreeRegenerationError(
            f"Unsupported package manager: {manager}"
        ) from exc


def _validate_manifest(root: Path, manager: str) -> Path:
    manifest = root / _manifest_for(manager)

    try:
        resolved = manifest.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencyTreeRegenerationError(
            f"Unable to resolve manifest: {manifest}"
        ) from exc

    if resolved.parent != root:
        raise DependencyTreeRegenerationError(
            f"Manifest escapes repository root: {manifest}"
        )

    if not resolved.is_file():
        raise DependencyTreeRegenerationError(
            f"Manifest is not a regular file: {manifest}"
        )

    if manifest.is_symlink():
        raise DependencyTreeRegenerationError(
            f"Symlink manifest is not allowed: {manifest}"
        )

    return resolved


def build_dependency_tree_command(manager: str) -> tuple[str, ...]:
    if manager not in SUPPORTED_MANAGERS:
        raise DependencyTreeRegenerationError(
            f"Unsupported package manager: {manager}"
        )

    return TREE_COMMANDS[manager]


def validate_request(request: DependencyTreeRequest) -> Path:
    if not isinstance(request, DependencyTreeRequest):
        raise DependencyTreeRegenerationError("Invalid request")

    manager = request.manager.strip().lower()

    if manager not in SUPPORTED_MANAGERS:
        raise DependencyTreeRegenerationError(
            f"Unsupported package manager: {request.manager}"
        )

    _validate_timeout(request.timeout)

    root = _repository_root(request.repository_root)
    return _validate_manifest(root, manager)


def _fingerprint(path: Path) -> DependencyTreeFingerprint:
    digest = hashlib.sha256()
    size = 0

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise DependencyTreeRegenerationError(
            f"Unable to fingerprint dependency tree: {path}"
        ) from exc

    return DependencyTreeFingerprint(
        path=path,
        sha256=digest.hexdigest(),
        size=size,
    )


def _parse_tree(manager: str, stdout: str) -> object | None:
    if manager in {"npm", "pnpm", "yarn"}:
        if not stdout.strip():
            return None

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise DependencyTreeRegenerationError(
                "Package-manager tree output is not valid JSON"
            ) from exc

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    return lines


def _safe_environment(
    request: DependencyTreeRequest,
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    if request.environment:
        for key, value in request.environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise DependencyTreeRegenerationError(
                    "Environment keys and values must be strings"
                )

            if key in {
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "PYTHONPATH",
                "NODE_OPTIONS",
                "BASH_ENV",
                "ENV",
            }:
                raise DependencyTreeRegenerationError(
                    f"Forbidden environment variable: {key}"
                )

            environment[key] = value

    return environment


def regenerate_dependency_tree(
    request: DependencyTreeRequest,
) -> DependencyTreeResult:
    root = validate_request(request)
    manager = request.manager.strip().lower()
    command = build_dependency_tree_command(manager)

    environment = _safe_environment(request)

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            close_fds=True,
            timeout=request.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return DependencyTreeResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            stdout=(
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            ),
            stderr=(
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            ),
            timed_out=True,
            tree=None,
            fingerprint=None,
            error="DEPENDENCY_TREE_TIMEOUT",
        )
    except OSError as exc:
        return DependencyTreeResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            stdout="",
            stderr="",
            timed_out=False,
            tree=None,
            fingerprint=None,
            error=f"DEPENDENCY_TREE_EXECUTION_ERROR: {exc}",
        )

    if completed.returncode != 0:
        return DependencyTreeResult(
            success=False,
            manager=manager,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            tree=None,
            fingerprint=None,
            error="DEPENDENCY_TREE_COMMAND_FAILED",
        )

    try:
        tree = _parse_tree(manager, completed.stdout)
    except DependencyTreeRegenerationError as exc:
        return DependencyTreeResult(
            success=False,
            manager=manager,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            tree=None,
            fingerprint=None,
            error=str(exc),
        )

    output_path = root / ".sentinelshield" / "dependency-tree.json"

    return DependencyTreeResult(
        success=True,
        manager=manager,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        tree=tree,
        fingerprint=None,
        error=None,
    )


def validate_dependency_tree_result(
    result: DependencyTreeResult,
) -> bool:
    if not isinstance(result, DependencyTreeResult):
        return False

    if result.timed_out:
        return False

    if result.success:
        if result.returncode != 0:
            return False
        if result.error is not None:
            return False
        if result.tree is None:
            return False
        if result.manager not in SUPPORTED_MANAGERS:
            return False

    return True


__all__ = [
    "DependencyTreeRegenerationError",
    "DependencyTreeFingerprint",
    "DependencyTreeRequest",
    "DependencyTreeResult",
    "SUPPORTED_MANAGERS",
    "build_dependency_tree_command",
    "validate_request",
    "regenerate_dependency_tree",
    "validate_dependency_tree_result",
]
