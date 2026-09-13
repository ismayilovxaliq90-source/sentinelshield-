from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class TransitiveDependencyChange:
    package: str
    before_version: str | None
    after_version: str | None
    before_parents: tuple[str, ...]
    after_parents: tuple[str, ...]
    change_type: str


@dataclass(frozen=True)
class TransitiveChangeAnalysisInput:
    before: Mapping[str, Mapping[str, object]]
    after: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class TransitiveChangeAnalysisResult:
    changes: tuple[TransitiveDependencyChange, ...]

    @property
    def added(self):
        return tuple(
            x for x in self.changes
            if x.change_type == "added"
        )

    @property
    def removed(self):
        return tuple(
            x for x in self.changes
            if x.change_type == "removed"
        )

    @property
    def updated(self):
        return tuple(
            x for x in self.changes
            if x.change_type == "updated"
        )

    @property
    def unchanged(self):
        return tuple(
            x for x in self.changes
            if x.change_type == "unchanged"
        )


def _validate_tree(tree, name):
    if not isinstance(tree, Mapping):
        raise TypeError(f"{name}_MUST_BE_MAPPING")

    for package, metadata in tree.items():
        if not isinstance(package, str):
            raise TypeError(
                f"{name}_PACKAGE_NAME_MUST_BE_STRING"
            )

        if not package.strip():
            raise ValueError(
                f"{name}_PACKAGE_NAME_MUST_NOT_BE_EMPTY"
            )

        if not isinstance(metadata, Mapping):
            raise TypeError(
                f"{name}_PACKAGE_METADATA_MUST_BE_MAPPING"
            )

        if "version" not in metadata:
            raise ValueError(
                f"{name}_PACKAGE_VERSION_REQUIRED"
            )

        version = metadata["version"]

        if version is not None and not isinstance(version, str):
            raise TypeError(
                f"{name}_PACKAGE_VERSION_MUST_BE_STRING_OR_NONE"
            )

        parents = metadata.get("parents", ())

        if isinstance(parents, (str, bytes)):
            raise TypeError(
                f"{name}_PACKAGE_PARENTS_MUST_BE_SEQUENCE"
            )

        try:
            tuple(parents)
        except TypeError as exc:
            raise TypeError(
                f"{name}_PACKAGE_PARENTS_MUST_BE_SEQUENCE"
            ) from exc

        direct = metadata.get("direct", False)

        if not isinstance(direct, bool):
            raise TypeError(
                f"{name}_PACKAGE_DIRECT_MUST_BE_BOOL"
            )


def _validate_input(request):
    if not isinstance(
        request,
        TransitiveChangeAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_TRANSITIVE_CHANGE_ANALYSIS_INPUT"
        )

    _validate_tree(request.before, "BEFORE")
    _validate_tree(request.after, "AFTER")

    return request


def _parents(metadata):
    return tuple(
        sorted(
            set(
                metadata.get("parents", ())
            )
        )
    )


def _is_transitive(metadata):
    return metadata.get("direct", False) is False


def analyze_transitive_changes(request):
    request = _validate_input(request)

    before = {
        package: metadata
        for package, metadata in request.before.items()
        if _is_transitive(metadata)
    }

    after = {
        package: metadata
        for package, metadata in request.after.items()
        if _is_transitive(metadata)
    }

    packages = sorted(set(before) | set(after))
    changes = []

    for package in packages:
        old = before.get(package)
        new = after.get(package)

        old_version = (
            old.get("version") if old is not None else None
        )

        new_version = (
            new.get("version") if new is not None else None
        )

        old_parents = (
            _parents(old) if old is not None else ()
        )

        new_parents = (
            _parents(new) if new is not None else ()
        )

        if old is None:
            change_type = "added"

        elif new is None:
            change_type = "removed"

        elif old_version != new_version:
            change_type = "updated"

        elif old_parents != new_parents:
            change_type = "updated"

        else:
            change_type = "unchanged"

        changes.append(
            TransitiveDependencyChange(
                package=package,
                before_version=old_version,
                after_version=new_version,
                before_parents=old_parents,
                after_parents=new_parents,
                change_type=change_type,
            )
        )

    return TransitiveChangeAnalysisResult(
        changes=tuple(changes)
    )


def transitive_change_analysis(request):
    return analyze_transitive_changes(request)
