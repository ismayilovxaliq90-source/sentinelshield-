from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Mapping, Iterable


__test__ = False


@dataclass(frozen=True)
class GeneratedFileImpact:
    path: str
    status: str
    is_tracked: bool
    is_sensitive: bool
    sha256: str | None


@dataclass(frozen=True)
class GeneratedFileImpactAnalysisInput:
    project_root: Path
    generated_files: Iterable[Path]
    tracked_files: Iterable[Path]
    sensitive_paths: Iterable[Path]


@dataclass(frozen=True)
class GeneratedFileImpactAnalysisResult:
    impacts: tuple[GeneratedFileImpact, ...]

    @property
    def added(self) -> tuple[GeneratedFileImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.status == "ADDED"
        )

    @property
    def modified(self) -> tuple[GeneratedFileImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.status == "MODIFIED"
        )

    @property
    def unchanged(self) -> tuple[GeneratedFileImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.status == "UNCHANGED"
        )

    @property
    def sensitive(self) -> tuple[GeneratedFileImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.status == "SENSITIVE"
        )

    @property
    def untracked_generated_files(self) -> tuple[GeneratedFileImpact, ...]:
        return tuple(
            item for item in self.impacts
            if not item.is_tracked
        )


def _validate_input(
    request: GeneratedFileImpactAnalysisInput,
) -> GeneratedFileImpactAnalysisInput:
    if not isinstance(
        request,
        GeneratedFileImpactAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_GENERATED_FILE_IMPACT_ANALYSIS_INPUT"
        )

    if not isinstance(request.project_root, Path):
        raise TypeError("PROJECT_ROOT_MUST_BE_PATH")

    if isinstance(request.generated_files, (str, bytes)):
        raise TypeError("GENERATED_FILES_MUST_BE_ITERABLE")

    if isinstance(request.tracked_files, (str, bytes)):
        raise TypeError("TRACKED_FILES_MUST_BE_ITERABLE")

    if isinstance(request.sensitive_paths, (str, bytes)):
        raise TypeError("SENSITIVE_PATHS_MUST_BE_ITERABLE")

    generated = tuple(
        _validate_path(item, "GENERATED_FILE")
        for item in request.generated_files
    )

    tracked = tuple(
        _validate_path(item, "TRACKED_FILE")
        for item in request.tracked_files
    )

    sensitive = tuple(
        _validate_path(item, "SENSITIVE_PATH")
        for item in request.sensitive_paths
    )

    return GeneratedFileImpactAnalysisInput(
        project_root=request.project_root,
        generated_files=tuple(dict.fromkeys(generated)),
        tracked_files=tuple(dict.fromkeys(tracked)),
        sensitive_paths=tuple(dict.fromkeys(sensitive)),
    )


def _validate_path(value: object, field: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field}_MUST_BE_PATH")

    if not str(value):
        raise ValueError(f"{field}_IS_EMPTY")

    return value


def _resolve_safe(
    root: Path,
    value: Path,
) -> Path:
    root = root.resolve()
    candidate = value if value.is_absolute() else root / value

    try:
        return candidate.resolve()
    except OSError as error:
        raise ValueError(
            "PATH_RESOLUTION_FAILED"
        ) from error


def _inside(
    path: Path,
    root: Path,
) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _relative_path(
    root: Path,
    path: Path,
) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None

    digest = sha256()

    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()


def _is_sensitive(
    path: Path,
    sensitive_roots: tuple[Path, ...],
) -> bool:
    return any(
        path == sensitive
        or _inside(path, sensitive)
        for sensitive in sensitive_roots
    )


def _is_tracked(
    path: Path,
    tracked: tuple[Path, ...],
) -> bool:
    return path in tracked


def _status(
    path: Path,
    project_root: Path,
    tracked: tuple[Path, ...],
    sensitive: tuple[Path, ...],
) -> tuple[str, bool, bool]:
    is_tracked = _is_tracked(path, tracked)
    is_sensitive = _is_sensitive(path, sensitive)

    if is_sensitive:
        return "SENSITIVE", is_tracked, True

    if not path.exists():
        return "UNCHANGED", is_tracked, False

    if not is_tracked:
        return "ADDED", False, False

    return "MODIFIED", True, False


def analyze_generated_file_impact(
    request: GeneratedFileImpactAnalysisInput,
) -> GeneratedFileImpactAnalysisResult:
    request = _validate_input(request)

    root = request.project_root.resolve()

    tracked = tuple(
        _resolve_safe(root, item)
        for item in request.tracked_files
    )

    sensitive = tuple(
        _resolve_safe(root, item)
        for item in request.sensitive_paths
    )

    impacts: list[GeneratedFileImpact] = []

    for generated in sorted(
        request.generated_files,
        key=lambda item: str(item),
    ):
        resolved = _resolve_safe(root, generated)

        if not _inside(resolved, root):
            raise ValueError(
                "GENERATED_FILE_OUTSIDE_PROJECT_ROOT"
            )

        status, is_tracked, is_sensitive = _status(
            resolved,
            root,
            tracked,
            sensitive,
        )

        impacts.append(
            GeneratedFileImpact(
                path=_relative_path(root, resolved),
                status=status,
                is_tracked=is_tracked,
                is_sensitive=is_sensitive,
                sha256=_sha256_file(resolved),
            )
        )

    return GeneratedFileImpactAnalysisResult(
        impacts=tuple(impacts),
    )


def generated_file_impact_analysis(
    request: GeneratedFileImpactAnalysisInput,
) -> GeneratedFileImpactAnalysisResult:
    return analyze_generated_file_impact(request)
