from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable, Mapping


class LockfileDiffAnalysisError(ValueError):
    """Raised when lockfile diff analysis input is invalid."""


class LockfileDiffState(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    EXPECTED_CHANGE = "EXPECTED_CHANGE"
    UNEXPECTED_CHANGE = "UNEXPECTED_CHANGE"


_MAX_PATH_LENGTH = 4096
_MAX_CONTENT_LENGTH = 8 * 1024 * 1024
_MAX_NAME_LENGTH = 512
_MAX_VERSION_LENGTH = 512


def _validate_text(value: object, field: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise LockfileDiffAnalysisError(
            f"{field} must be a string"
        )
    if not value or not value.strip():
        raise LockfileDiffAnalysisError(
            f"{field} must not be empty"
        )
    if len(value) > max_length:
        raise LockfileDiffAnalysisError(
            f"{field} exceeds maximum length"
        )
    if "\x00" in value:
        raise LockfileDiffAnalysisError(
            f"{field} contains a NULL character"
        )
    return value


def _normalize_path(path: object) -> str:
    value = _validate_text(path, "path", _MAX_PATH_LENGTH).strip()

    if "\\" in value:
        raise LockfileDiffAnalysisError(
            "path must use POSIX separators"
        )

    if value.startswith("/"):
        raise LockfileDiffAnalysisError(
            "absolute paths are not allowed"
        )

    parts = PurePosixPath(value).parts

    if not parts or value == ".":
        raise LockfileDiffAnalysisError(
            "invalid repository-relative path"
        )

    if any(part in ("", ".", "..") for part in parts):
        raise LockfileDiffAnalysisError(
            "path contains invalid traversal components"
        )

    return str(PurePosixPath(*parts))


def _normalize_paths(paths: Iterable[str]) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes)):
        raise LockfileDiffAnalysisError(
            "paths must be an iterable of path strings"
        )

    try:
        normalized = {_normalize_path(path) for path in paths}
    except TypeError as exc:
        raise LockfileDiffAnalysisError(
            "paths must be iterable"
        ) from exc

    return tuple(sorted(normalized))


def _normalize_version(value: object, field: str) -> str:
    return _validate_text(
        value,
        field,
        _MAX_VERSION_LENGTH,
    ).strip()


@dataclass(frozen=True)
class LockfileEntry:
    name: str
    version: str

    def __post_init__(self) -> None:
        name = _validate_text(
            self.name,
            "name",
            _MAX_NAME_LENGTH,
        ).strip()
        version = _normalize_version(
            self.version,
            "version",
        )

        if name != self.name:
            object.__setattr__(self, "name", name)

        if version != self.version:
            object.__setattr__(self, "version", version)

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
        }


@dataclass(frozen=True)
class LockfileEntryChange:
    name: str
    baseline_versions: tuple[str, ...]
    current_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        name = _validate_text(
            self.name,
            "name",
            _MAX_NAME_LENGTH,
        ).strip()

        baseline = tuple(
            sorted(
                {
                    _normalize_version(version, "baseline_version")
                    for version in self.baseline_versions
                }
            )
        )

        current = tuple(
            sorted(
                {
                    _normalize_version(version, "current_version")
                    for version in self.current_versions
                }
            )
        )

        if not baseline and not current:
            raise LockfileDiffAnalysisError(
                "entry change must contain a baseline or current version"
            )

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "baseline_versions", baseline)
        object.__setattr__(self, "current_versions", current)

    @property
    def is_added(self) -> bool:
        return not self.baseline_versions and bool(self.current_versions)

    @property
    def is_removed(self) -> bool:
        return bool(self.baseline_versions) and not self.current_versions

    @property
    def is_version_changed(self) -> bool:
        return (
            bool(self.baseline_versions)
            and bool(self.current_versions)
            and self.baseline_versions != self.current_versions
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "baseline_versions": list(self.baseline_versions),
            "current_versions": list(self.current_versions),
            "is_added": self.is_added,
            "is_removed": self.is_removed,
            "is_version_changed": self.is_version_changed,
        }


@dataclass(frozen=True)
class LockfileDiffAnalysisResult:
    state: LockfileDiffState
    changed_lockfiles: tuple[str, ...]
    added_entries: tuple[LockfileEntryChange, ...]
    removed_entries: tuple[LockfileEntryChange, ...]
    changed_entries: tuple[LockfileEntryChange, ...]
    expected_changes: tuple[str, ...]
    unexpected_changes: tuple[str, ...]
    valid: bool

    def __post_init__(self) -> None:
        if not isinstance(self.state, LockfileDiffState):
            try:
                object.__setattr__(
                    self,
                    "state",
                    LockfileDiffState(self.state),
                )
            except (TypeError, ValueError) as exc:
                raise LockfileDiffAnalysisError(
                    "invalid lockfile diff state"
                ) from exc

        object.__setattr__(
            self,
            "changed_lockfiles",
            _normalize_paths(self.changed_lockfiles),
        )

        object.__setattr__(
            self,
            "expected_changes",
            _normalize_paths(self.expected_changes),
        )

        object.__setattr__(
            self,
            "unexpected_changes",
            _normalize_paths(self.unexpected_changes),
        )

        added = tuple(
            sorted(
                self.added_entries,
                key=lambda item: item.name,
            )
        )
        removed = tuple(
            sorted(
                self.removed_entries,
                key=lambda item: item.name,
            )
        )
        changed = tuple(
            sorted(
                self.changed_entries,
                key=lambda item: item.name,
            )
        )

        for collection in (added, removed, changed):
            for item in collection:
                if not isinstance(item, LockfileEntryChange):
                    raise LockfileDiffAnalysisError(
                        "entry collections contain invalid values"
                    )

        object.__setattr__(self, "added_entries", added)
        object.__setattr__(self, "removed_entries", removed)
        object.__setattr__(self, "changed_entries", changed)

        if not isinstance(self.valid, bool):
            raise LockfileDiffAnalysisError(
                "valid must be a boolean"
            )

        if self.state == LockfileDiffState.NO_CHANGE:
            if self.unexpected_changes:
                raise LockfileDiffAnalysisError(
                    "NO_CHANGE cannot contain unexpected changes"
                )

        if self.state == LockfileDiffState.EXPECTED_CHANGE:
            if not self.valid or self.unexpected_changes:
                raise LockfileDiffAnalysisError(
                    "EXPECTED_CHANGE must be valid and contain no unexpected changes"
                )

        if self.state == LockfileDiffState.UNEXPECTED_CHANGE:
            if self.valid or not self.unexpected_changes:
                raise LockfileDiffAnalysisError(
                    "UNEXPECTED_CHANGE must be invalid and contain unexpected changes"
                )

        if not set(self.changed_lockfiles).issuperset(
            set(self.expected_changes)
        ):
            raise LockfileDiffAnalysisError(
                "expected lockfiles must be included in changed_lockfiles"
            )

    @property
    def has_changes(self) -> bool:
        return bool(
            self.changed_lockfiles
            or self.added_entries
            or self.removed_entries
            or self.changed_entries
        )

    @property
    def is_safe(self) -> bool:
        return self.valid and not self.unexpected_changes

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "changed_lockfiles": list(self.changed_lockfiles),
            "added_entries": [
                item.to_dict() for item in self.added_entries
            ],
            "removed_entries": [
                item.to_dict() for item in self.removed_entries
            ],
            "changed_entries": [
                item.to_dict() for item in self.changed_entries
            ],
            "expected_changes": list(self.expected_changes),
            "unexpected_changes": list(self.unexpected_changes),
            "valid": self.valid,
            "has_changes": self.has_changes,
            "is_safe": self.is_safe,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )


def _normalize_entries(
    entries: Iterable[LockfileEntry | Mapping[str, object]],
) -> tuple[LockfileEntry, ...]:
    if isinstance(entries, (str, bytes)):
        raise LockfileDiffAnalysisError(
            "entries must be iterable"
        )

    normalized: list[LockfileEntry] = []

    try:
        iterator = iter(entries)
    except TypeError as exc:
        raise LockfileDiffAnalysisError(
            "entries must be iterable"
        ) from exc

    for entry in iterator:
        if isinstance(entry, LockfileEntry):
            normalized.append(entry)
            continue

        if isinstance(entry, Mapping):
            try:
                normalized.append(
                    LockfileEntry(
                        name=entry["name"],
                        version=entry["version"],
                    )
                )
            except KeyError as exc:
                raise LockfileDiffAnalysisError(
                    "entry requires name and version"
                ) from exc
            continue

        raise LockfileDiffAnalysisError(
            "entry must be LockfileEntry or mapping"
        )

    return tuple(normalized)


def _entry_versions(
    entries: tuple[LockfileEntry, ...],
) -> dict[str, tuple[str, ...]]:
    result: dict[str, set[str]] = {}

    for entry in entries:
        result.setdefault(entry.name, set()).add(entry.version)

    return {
        name: tuple(sorted(versions))
        for name, versions in sorted(result.items())
    }


def _build_changes(
    baseline: dict[str, tuple[str, ...]],
    current: dict[str, tuple[str, ...]],
) -> tuple[
    tuple[LockfileEntryChange, ...],
    tuple[LockfileEntryChange, ...],
    tuple[LockfileEntryChange, ...],
]:
    added: list[LockfileEntryChange] = []
    removed: list[LockfileEntryChange] = []
    changed: list[LockfileEntryChange] = []

    for name in sorted(set(current) - set(baseline)):
        added.append(
            LockfileEntryChange(
                name=name,
                baseline_versions=(),
                current_versions=current[name],
            )
        )

    for name in sorted(set(baseline) - set(current)):
        removed.append(
            LockfileEntryChange(
                name=name,
                baseline_versions=baseline[name],
                current_versions=(),
            )
        )

    for name in sorted(set(baseline) & set(current)):
        if baseline[name] != current[name]:
            changed.append(
                LockfileEntryChange(
                    name=name,
                    baseline_versions=baseline[name],
                    current_versions=current[name],
                )
            )

    return tuple(added), tuple(removed), tuple(changed)


def _change_key(change: LockfileEntryChange) -> str:
    if change.is_added:
        return f"ADD:{change.name}:{','.join(change.current_versions)}"
    if change.is_removed:
        return f"REMOVE:{change.name}:{','.join(change.baseline_versions)}"
    return (
        f"CHANGE:{change.name}:"
        f"{','.join(change.baseline_versions)}->"
        f"{','.join(change.current_versions)}"
    )


def _normalize_expected_change(value: object) -> str:
    text = _validate_text(
        value,
        "expected_change",
        _MAX_NAME_LENGTH + _MAX_VERSION_LENGTH * 2,
    ).strip()

    if text.startswith("ADD:") or text.startswith("REMOVE:"):
        prefix, _, rest = text.partition(":")
        if not rest:
            raise LockfileDiffAnalysisError(
                "invalid expected change"
            )
        return text

    if text.startswith("CHANGE:"):
        if "->" not in text:
            raise LockfileDiffAnalysisError(
                "invalid CHANGE expected change"
            )
        return text

    raise LockfileDiffAnalysisError(
        "expected change must use ADD:, REMOVE:, or CHANGE:"
    )


def analyze_lockfile_diff(
    baseline_entries: Iterable[LockfileEntry | Mapping[str, object]],
    current_entries: Iterable[LockfileEntry | Mapping[str, object]],
    *,
    changed_lockfiles: Iterable[str] = (),
    expected_changes: Iterable[str] = (),
) -> LockfileDiffAnalysisResult:
    baseline = _entry_versions(
        _normalize_entries(baseline_entries)
    )
    current = _entry_versions(
        _normalize_entries(current_entries)
    )

    changed_paths = _normalize_paths(changed_lockfiles)

    if isinstance(expected_changes, (str, bytes)):
        raise LockfileDiffAnalysisError(
            "expected_changes must be iterable"
        )

    normalized_expected = tuple(
        sorted(
            {
                _normalize_expected_change(item)
                for item in expected_changes
            }
        )
    )

    added, removed, changed = _build_changes(
        baseline,
        current,
    )

    all_changes = added + removed + changed
    actual_change_keys = {
        _change_key(change)
        for change in all_changes
    }

    expected_set = set(normalized_expected)
    unexpected = tuple(
        sorted(actual_change_keys - expected_set)
    )

    has_actual_entry_change = bool(all_changes)

    if not has_actual_entry_change and not changed_paths:
        state = LockfileDiffState.NO_CHANGE
        valid = True
        expected_result: tuple[str, ...] = ()
        unexpected_result: tuple[str, ...] = ()

    elif unexpected:
        state = LockfileDiffState.UNEXPECTED_CHANGE
        valid = False
        expected_result = tuple(
            sorted(actual_change_keys & expected_set)
        )
        unexpected_result = unexpected

    else:
        state = LockfileDiffState.EXPECTED_CHANGE
        valid = True
        expected_result = tuple(sorted(actual_change_keys))
        unexpected_result = ()

    return LockfileDiffAnalysisResult(
        state=state,
        changed_lockfiles=changed_paths,
        added_entries=added,
        removed_entries=removed,
        changed_entries=changed,
        expected_changes=expected_result,
        unexpected_changes=unexpected_result,
        valid=valid,
    )


def validate_lockfile_diff_result(
    result: LockfileDiffAnalysisResult,
) -> bool:
    if not isinstance(result, LockfileDiffAnalysisResult):
        return False

    try:
        LockfileDiffAnalysisResult(
            state=result.state,
            changed_lockfiles=result.changed_lockfiles,
            added_entries=result.added_entries,
            removed_entries=result.removed_entries,
            changed_entries=result.changed_entries,
            expected_changes=result.expected_changes,
            unexpected_changes=result.unexpected_changes,
            valid=result.valid,
        )
    except (LockfileDiffAnalysisError, TypeError, ValueError):
        return False

    return True


def analyze_lockfile_content(
    baseline_content: str,
    current_content: str,
    *,
    lockfile_path: str,
    expected_changes: Iterable[str] = (),
) -> LockfileDiffAnalysisResult:
    baseline_text = _validate_text(
        baseline_content,
        "baseline_content",
        _MAX_CONTENT_LENGTH,
    )

    current_text = _validate_text(
        current_content,
        "current_content",
        _MAX_CONTENT_LENGTH,
    )

    normalized_path = _normalize_path(lockfile_path)

    if baseline_text == current_text:
        return analyze_lockfile_diff(
            (),
            (),
            changed_lockfiles=(),
            expected_changes=expected_changes,
        )

    baseline_hash = hashlib.sha256(
        baseline_text.encode("utf-8")
    ).hexdigest()
    current_hash = hashlib.sha256(
        current_text.encode("utf-8")
    ).hexdigest()

    synthetic_baseline = (
        LockfileEntry(
            name=f"__lockfile_hash__:{normalized_path}",
            version=baseline_hash,
        ),
    )
    synthetic_current = (
        LockfileEntry(
            name=f"__lockfile_hash__:{normalized_path}",
            version=current_hash,
        ),
    )

    return analyze_lockfile_diff(
        synthetic_baseline,
        synthetic_current,
        changed_lockfiles=(normalized_path,),
        expected_changes=expected_changes,
    )
