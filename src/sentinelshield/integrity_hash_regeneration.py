from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class IntegrityHashError(RuntimeError):
    """Raised when integrity/hash processing cannot be completed safely."""


SUPPORTED_ALGORITHMS = frozenset({"sha256"})
MAX_FILE_SIZE = 512 * 1024 * 1024


@dataclass(frozen=True)
class IntegrityHash:
    path: Path
    algorithm: str
    digest: str
    size: int

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "algorithm": self.algorithm,
            "digest": self.digest,
            "size": self.size,
        }


@dataclass(frozen=True)
class IntegrityHashRequest:
    repository_root: Path
    paths: tuple[Path, ...]
    algorithm: str = "sha256"
    max_file_size: int = MAX_FILE_SIZE


@dataclass(frozen=True)
class IntegrityHashResult:
    success: bool
    algorithm: str
    hashes: tuple[IntegrityHash, ...]
    failed_paths: tuple[str, ...]
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "algorithm": self.algorithm,
            "hashes": [item.to_dict() for item in self.hashes],
            "failed_paths": list(self.failed_paths),
            "error": self.error,
        }


def _resolve_repository_root(path: Path) -> Path:
    if not isinstance(path, Path):
        raise IntegrityHashError("repository_root must be a Path")

    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IntegrityHashError(
            f"Unable to resolve repository root: {path}"
        ) from exc

    if not root.is_dir():
        raise IntegrityHashError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise IntegrityHashError(
            f"Not a Git repository: {root}"
        )

    return root


def _validate_algorithm(algorithm: str) -> str:
    if not isinstance(algorithm, str):
        raise IntegrityHashError("algorithm must be a string")

    normalized = algorithm.strip().lower()

    if normalized not in SUPPORTED_ALGORITHMS:
        raise IntegrityHashError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    return normalized


def _validate_size_limit(max_file_size: int) -> None:
    if isinstance(max_file_size, bool):
        raise IntegrityHashError("Invalid max_file_size")

    if not isinstance(max_file_size, int):
        raise IntegrityHashError("max_file_size must be an integer")

    if max_file_size <= 0 or max_file_size > MAX_FILE_SIZE:
        raise IntegrityHashError(
            f"max_file_size must be between 1 and {MAX_FILE_SIZE}"
        )


def _validate_file(root: Path, candidate: Path) -> Path:
    if not isinstance(candidate, Path):
        raise IntegrityHashError(
            f"Invalid integrity path: {candidate!r}"
        )

    if candidate.is_symlink():
        raise IntegrityHashError(
            f"Symlink is not allowed: {candidate}"
        )

    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IntegrityHashError(
            f"Unable to resolve integrity path: {candidate}"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise IntegrityHashError(
            f"Path escapes repository root: {candidate}"
        ) from exc

    if not resolved.is_file():
        raise IntegrityHashError(
            f"Not a regular file: {resolved}"
        )

    if resolved.is_symlink():
        raise IntegrityHashError(
            f"Resolved path is a symlink: {resolved}"
        )

    return resolved


def validate_request(request: IntegrityHashRequest) -> Path:
    if not isinstance(request, IntegrityHashRequest):
        raise IntegrityHashError("Invalid integrity request")

    root = _resolve_repository_root(request.repository_root)
    _validate_algorithm(request.algorithm)
    _validate_size_limit(request.max_file_size)

    if not request.paths:
        raise IntegrityHashError("At least one path is required")

    for path in request.paths:
        _validate_file(root, path)

    return root


def calculate_sha256(path: Path, max_file_size: int = MAX_FILE_SIZE) -> IntegrityHash:
    if not isinstance(path, Path):
        raise IntegrityHashError("path must be a Path")

    _validate_size_limit(max_file_size)

    if path.is_symlink():
        raise IntegrityHashError(
            f"Symlink is not allowed: {path}"
        )

    try:
        stat = path.stat()
    except OSError as exc:
        raise IntegrityHashError(
            f"Unable to inspect file: {path}"
        ) from exc

    if not path.is_file():
        raise IntegrityHashError(
            f"Not a regular file: {path}"
        )

    if stat.st_size > max_file_size:
        raise IntegrityHashError(
            f"File exceeds configured size limit: {path}"
        )

    digest = hashlib.sha256()
    total = 0

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)

                if not chunk:
                    break

                total += len(chunk)

                if total > max_file_size:
                    raise IntegrityHashError(
                        f"File exceeds configured size limit: {path}"
                    )

                digest.update(chunk)
    except IntegrityHashError:
        raise
    except OSError as exc:
        raise IntegrityHashError(
            f"Unable to hash file: {path}"
        ) from exc

    return IntegrityHash(
        path=path,
        algorithm="sha256",
        digest=digest.hexdigest(),
        size=total,
    )


def regenerate_integrity_hashes(
    request: IntegrityHashRequest,
) -> IntegrityHashResult:
    root = validate_request(request)
    algorithm = _validate_algorithm(request.algorithm)

    hashes: list[IntegrityHash] = []
    failures: list[str] = []

    for candidate in request.paths:
        try:
            path = _validate_file(root, candidate)

            if algorithm != "sha256":
                raise IntegrityHashError(
                    f"Unsupported hash algorithm: {algorithm}"
                )

            hashes.append(
                calculate_sha256(
                    path,
                    max_file_size=request.max_file_size,
                )
            )
        except IntegrityHashError:
            failures.append(str(candidate))

    if failures:
        return IntegrityHashResult(
            success=False,
            algorithm=algorithm,
            hashes=tuple(hashes),
            failed_paths=tuple(failures),
            error="INTEGRITY_HASH_REGENERATION_FAILED",
        )

    return IntegrityHashResult(
        success=True,
        algorithm=algorithm,
        hashes=tuple(hashes),
        failed_paths=(),
        error=None,
    )


def validate_integrity_hash(
    integrity: IntegrityHash,
) -> bool:
    if not isinstance(integrity, IntegrityHash):
        return False

    if integrity.algorithm != "sha256":
        return False

    if not isinstance(integrity.digest, str):
        return False

    if len(integrity.digest) != 64:
        return False

    if any(character not in "0123456789abcdef"
           for character in integrity.digest):
        return False

    if not isinstance(integrity.size, int) or integrity.size < 0:
        return False

    return True


def validate_integrity_result(
    result: IntegrityHashResult,
) -> bool:
    if not isinstance(result, IntegrityHashResult):
        return False

    if result.algorithm not in SUPPORTED_ALGORITHMS:
        return False

    if result.success and result.error is not None:
        return False

    if result.success and result.failed_paths:
        return False

    return all(
        validate_integrity_hash(item)
        for item in result.hashes
    )


def regenerate_from_paths(
    repository_root: Path,
    paths: Iterable[Path],
) -> IntegrityHashResult:
    return regenerate_integrity_hashes(
        IntegrityHashRequest(
            repository_root=repository_root,
            paths=tuple(paths),
        )
    )


__all__ = [
    "IntegrityHashError",
    "IntegrityHash",
    "IntegrityHashRequest",
    "IntegrityHashResult",
    "SUPPORTED_ALGORITHMS",
    "MAX_FILE_SIZE",
    "calculate_sha256",
    "validate_request",
    "regenerate_integrity_hashes",
    "validate_integrity_hash",
    "validate_integrity_result",
    "regenerate_from_paths",
]
