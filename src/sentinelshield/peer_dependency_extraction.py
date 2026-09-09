from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class PeerDependency:
    name: str
    version: str
    dependency_type: str = "peer"
    source: str = "peerDependencies"


@dataclass(frozen=True)
class PeerDependencyExtractionResult:
    manifest_path: Optional[Path]
    dependencies: tuple[PeerDependency, ...]
    extracted: bool
    status: str


def _resolve_manifest_path(
    manifest_path: object,
) -> tuple[Optional[Path], str]:
    if manifest_path is None:
        return None, "PATH_IS_NONE"

    if not isinstance(manifest_path, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(manifest_path).strip()

    if not raw:
        return None, "PATH_IS_EMPTY"

    if "\x00" in raw:
        return None, "NULL_CHARACTER_NOT_ALLOWED"

    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except FileNotFoundError:
        return None, "PATH_NOT_FOUND"
    except OSError:
        return None, "PATH_RESOLUTION_ERROR"

    try:
        if not path.is_file():
            return None, "NOT_A_FILE"
    except OSError:
        return None, "FILESYSTEM_ERROR"

    return path, "VALID"


def _read_manifest(
    path: Path,
) -> tuple[Optional[dict], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError):
        return None, "READ_ERROR"
    except json.JSONDecodeError:
        return None, "PARSE_ERROR"

    if not isinstance(data, dict):
        return None, "INVALID_MANIFEST_STRUCTURE"

    return data, "VALID"


def _extract_peer_dependencies(
    data: dict,
) -> tuple[tuple[PeerDependency, ...], str]:
    section = data.get("peerDependencies")

    if section is None:
        return (), "NO_PEER_DEPENDENCIES"

    if not isinstance(section, dict):
        return (), "INVALID_PEER_DEPENDENCY_SECTION"

    dependencies: list[PeerDependency] = []

    for name, version in section.items():
        if not isinstance(name, str) or not name.strip():
            return (), "INVALID_DEPENDENCY_NAME"

        if not isinstance(version, str):
            return (), "INVALID_DEPENDENCY_VERSION"

        dependencies.append(
            PeerDependency(
                name=name,
                version=version,
            )
        )

    dependencies.sort(
        key=lambda dependency: (
            dependency.name.lower(),
            dependency.version,
        )
    )

    return tuple(dependencies), "EXTRACTED"


def extract_peer_dependencies(
    manifest_path: object,
) -> PeerDependencyExtractionResult:
    """
    Extract peer dependencies from package.json.

    Supported manifest:
        - package.json

    Only the peerDependencies section is extracted.

    This operation is strictly read-only.
    It does not install packages, modify files, regenerate lockfiles,
    execute package-manager commands, or execute project code.
    """
    path, status = _resolve_manifest_path(manifest_path)

    if path is None:
        return PeerDependencyExtractionResult(
            manifest_path=None,
            dependencies=(),
            extracted=False,
            status=status,
        )

    if path.name.lower() != "package.json":
        return PeerDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_MANIFEST",
        )

    data, read_status = _read_manifest(path)

    if data is None:
        return PeerDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status=read_status,
        )

    dependencies, extraction_status = _extract_peer_dependencies(data)

    return PeerDependencyExtractionResult(
        manifest_path=path,
        dependencies=dependencies,
        extracted=extraction_status in {
            "EXTRACTED",
            "NO_PEER_DEPENDENCIES",
        },
        status=extraction_status,
    )
