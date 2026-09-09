from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class ManifestLockfileRelationship:
    manifest: Path
    lockfiles: tuple[Path, ...]


@dataclass(frozen=True)
class ManifestLockfileRelationshipMappingResult:
    repository_root: Optional[Path]
    relationships: tuple[ManifestLockfileRelationship, ...]
    unmatched_manifests: tuple[Path, ...]
    unmatched_lockfiles: tuple[Path, ...]
    found: bool
    status: str


MANIFEST_LOCKFILE_PAIRS = {
    "package.json": (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ),
    "cargo.toml": (
        "cargo.lock",
    ),
    "composer.json": (
        "composer.lock",
    ),
    "pipfile": (
        "pipfile.lock",
    ),
    "pyproject.toml": (
        "poetry.lock",
    ),
}


def _resolve_root(
    repository_root: object,
) -> tuple[Optional[Path], str]:
    if repository_root is None:
        return None, "PATH_IS_NONE"

    if not isinstance(repository_root, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(repository_root).strip()

    if not raw:
        return None, "PATH_IS_EMPTY"

    if "\x00" in raw:
        return None, "NULL_CHARACTER_NOT_ALLOWED"

    try:
        root = Path(raw).expanduser().resolve(strict=True)
    except FileNotFoundError:
        return None, "PATH_NOT_FOUND"
    except OSError:
        return None, "PATH_RESOLUTION_ERROR"

    try:
        if not root.is_dir():
            return None, "NOT_A_DIRECTORY"
    except OSError:
        return None, "FILESYSTEM_ERROR"

    return root, "VALID"


def _discover_files(root: Path) -> tuple[Path, ...]:
    discovered: list[Path] = []

    try:
        for current_root, dir_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)

            dir_names[:] = [
                name
                for name in dir_names
                if not (current / name).is_symlink()
            ]

            for filename in file_names:
                candidate = current / filename

                try:
                    if candidate.is_symlink():
                        continue

                    if not candidate.is_file():
                        continue

                    resolved = candidate.resolve(strict=True)

                    if not resolved.is_file():
                        continue

                    resolved.relative_to(root)
                    discovered.append(resolved)

                except (OSError, RuntimeError, ValueError):
                    continue

    except (OSError, RuntimeError):
        return ()

    return tuple(sorted(set(discovered), key=str))


def map_manifest_lockfile_relationships(
    repository_root: object,
) -> ManifestLockfileRelationshipMappingResult:
    root, status = _resolve_root(repository_root)

    if root is None:
        return ManifestLockfileRelationshipMappingResult(
            repository_root=None,
            relationships=(),
            unmatched_manifests=(),
            unmatched_lockfiles=(),
            found=False,
            status=status,
        )

    files = _discover_files(root)

    if not files and any(root.iterdir()):
        return ManifestLockfileRelationshipMappingResult(
            repository_root=root,
            relationships=(),
            unmatched_manifests=(),
            unmatched_lockfiles=(),
            found=False,
            status="DISCOVERY_ERROR",
        )

    manifests_by_name: dict[str, list[Path]] = {}
    lockfiles_by_name: dict[str, list[Path]] = {}

    manifest_names = set(MANIFEST_LOCKFILE_PAIRS)
    lockfile_names = {
        lockfile
        for lockfiles in MANIFEST_LOCKFILE_PAIRS.values()
        for lockfile in lockfiles
    }

    for path in files:
        name = path.name.lower()

        if name in manifest_names:
            manifests_by_name.setdefault(name, []).append(path)

        if name in lockfile_names:
            lockfiles_by_name.setdefault(name, []).append(path)

    relationships: list[ManifestLockfileRelationship] = []
    matched_manifests: set[Path] = set()
    matched_lockfiles: set[Path] = set()

    for manifest_name in sorted(manifests_by_name):
        for manifest in sorted(manifests_by_name[manifest_name], key=str):
            matched: list[Path] = []

            for lockfile_name in MANIFEST_LOCKFILE_PAIRS[manifest_name]:
                candidates = lockfiles_by_name.get(lockfile_name, [])

                for lockfile in candidates:
                    try:
                        lockfile.relative_to(manifest.parent)
                    except ValueError:
                        continue

                    matched.append(lockfile)

            matched = sorted(set(matched), key=str)

            if matched:
                relationships.append(
                    ManifestLockfileRelationship(
                        manifest=manifest,
                        lockfiles=tuple(matched),
                    )
                )
                matched_manifests.add(manifest)
                matched_lockfiles.update(matched)

    all_manifests = {
        path
        for paths in manifests_by_name.values()
        for path in paths
    }

    all_lockfiles = {
        path
        for paths in lockfiles_by_name.values()
        for path in paths
    }

    unmatched_manifests = tuple(
        sorted(all_manifests - matched_manifests, key=str)
    )

    unmatched_lockfiles = tuple(
        sorted(all_lockfiles - matched_lockfiles, key=str)
    )

    relationships = sorted(
        relationships,
        key=lambda item: str(item.manifest),
    )

    found = bool(relationships)

    return ManifestLockfileRelationshipMappingResult(
        repository_root=root,
        relationships=tuple(relationships),
        unmatched_manifests=unmatched_manifests,
        unmatched_lockfiles=unmatched_lockfiles,
        found=found,
        status="FOUND" if found else "NOT_FOUND",
    )
