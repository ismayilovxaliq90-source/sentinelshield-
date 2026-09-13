from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


__test__ = False


@dataclass(frozen=True)
class UnrelatedChange:
    path: str
    change_type: str
    unrelated: bool
    reason: str


@dataclass(frozen=True)
class UnrelatedChangeDetectionInput:
    changed_files: Iterable[str]
    allowed_files: Iterable[str]
    allowed_prefixes: Iterable[str] = ()


@dataclass(frozen=True)
class UnrelatedChangeDetectionResult:
    changes: tuple[UnrelatedChange, ...]

    @property
    def unrelated(self) -> tuple[UnrelatedChange, ...]:
        return tuple(
            item for item in self.changes
            if item.unrelated
        )

    @property
    def related(self) -> tuple[UnrelatedChange, ...]:
        return tuple(
            item for item in self.changes
            if not item.unrelated
        )

    @property
    def has_unrelated_changes(self) -> bool:
        return bool(self.unrelated)


def _normalize(value: str) -> str:
    value = value.strip().replace("\\", "/")

    while value.startswith("./"):
        value = value[2:]

    return value.rstrip("/") if value != "/" else value


def _validate_input(
    request: UnrelatedChangeDetectionInput,
) -> UnrelatedChangeDetectionInput:
    if not isinstance(
        request,
        UnrelatedChangeDetectionInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_UNRELATED_CHANGE_DETECTION_INPUT"
        )

    for name, values in (
        ("CHANGED_FILES", request.changed_files),
        ("ALLOWED_FILES", request.allowed_files),
        ("ALLOWED_PREFIXES", request.allowed_prefixes),
    ):
        if isinstance(values, (str, bytes)):
            raise TypeError(
                f"{name}_MUST_BE_ITERABLE"
            )

    changed: list[str] = []

    for value in request.changed_files:
        if not isinstance(value, str):
            raise TypeError(
                "CHANGED_FILE_MUST_BE_STRING"
            )

        normalized = _normalize(value)

        if not normalized:
            raise ValueError(
                "CHANGED_FILE_IS_EMPTY"
            )

        changed.append(normalized)

    allowed: list[str] = []

    for value in request.allowed_files:
        if not isinstance(value, str):
            raise TypeError(
                "ALLOWED_FILE_MUST_BE_STRING"
            )

        normalized = _normalize(value)

        if not normalized:
            raise ValueError(
                "ALLOWED_FILE_IS_EMPTY"
            )

        allowed.append(normalized)

    prefixes: list[str] = []

    for value in request.allowed_prefixes:
        if not isinstance(value, str):
            raise TypeError(
                "ALLOWED_PREFIX_MUST_BE_STRING"
            )

        normalized = _normalize(value)

        if not normalized:
            raise ValueError(
                "ALLOWED_PREFIX_IS_EMPTY"
            )

        prefixes.append(normalized)

    return UnrelatedChangeDetectionInput(
        changed_files=tuple(dict.fromkeys(changed)),
        allowed_files=tuple(dict.fromkeys(allowed)),
        allowed_prefixes=tuple(dict.fromkeys(prefixes)),
    )


def _matches_prefix(
    path: str,
    prefix: str,
) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _is_allowed(
    path: str,
    allowed_files: tuple[str, ...],
    allowed_prefixes: tuple[str, ...],
) -> bool:
    if path in allowed_files:
        return True

    return any(
        _matches_prefix(path, prefix)
        for prefix in allowed_prefixes
    )


def _change_type(path: str) -> str:
    suffix = Path(path).suffix.lower()

    if suffix in {".lock", ".sum"}:
        return "DEPENDENCY_METADATA"

    if suffix in {
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".cpp",
        ".c",
    }:
        return "SOURCE"

    if Path(path).name.startswith("test_"):
        return "TEST"

    if Path(path).name.endswith(("_test.py", ".spec.js", ".spec.ts")):
        return "TEST"

    if suffix in {
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
    }:
        return "CONFIGURATION"

    return "OTHER"


def detect_unrelated_changes(
    request: UnrelatedChangeDetectionInput,
) -> UnrelatedChangeDetectionResult:
    request = _validate_input(request)

    changed = tuple(request.changed_files)
    allowed_files = tuple(request.allowed_files)
    allowed_prefixes = tuple(request.allowed_prefixes)

    results: list[UnrelatedChange] = []

    for path in sorted(changed):
        if _is_allowed(
            path,
            allowed_files,
            allowed_prefixes,
        ):
            results.append(
                UnrelatedChange(
                    path=path,
                    change_type=_change_type(path),
                    unrelated=False,
                    reason="CHANGE_WITHIN_REMEDIATION_SCOPE",
                )
            )
        else:
            results.append(
                UnrelatedChange(
                    path=path,
                    change_type=_change_type(path),
                    unrelated=True,
                    reason="CHANGE_OUTSIDE_REMEDIATION_SCOPE",
                )
            )

    return UnrelatedChangeDetectionResult(
        changes=tuple(results),
    )


def unrelated_change_detection(
    request: UnrelatedChangeDetectionInput,
) -> UnrelatedChangeDetectionResult:
    return detect_unrelated_changes(request)
