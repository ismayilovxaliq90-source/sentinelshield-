from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class OptionalDependency:
    name: str
    version: str
    dependency_type: str = "optional"
    source: str = "optionalDependencies"


@dataclass(frozen=True)
class OptionalDependencyExtractionResult:
    manifest_path: Optional[Path]
    dependencies: tuple[OptionalDependency, ...]
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


def _read_json_manifest(
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


def _extract_optional_dependencies(
    data: dict,
) -> tuple[tuple[OptionalDependency, ...], str]:
    section = data.get("optionalDependencies")

    if section is None:
        return (), "NO_OPTIONAL_DEPENDENCIES"

    if not isinstance(section, dict):
        return (), "INVALID_OPTIONAL_DEPENDENCY_SECTION"

    dependencies: list[OptionalDependency] = []

    for name, version in section.items():
        if not isinstance(name, str) or not name.strip():
            return (), "INVALID_DEPENDENCY_NAME"

        if not isinstance(version, str):
            return (), "INVALID_DEPENDENCY_VERSION"

        dependencies.append(
            OptionalDependency(
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


def extract_optional_dependencies(
    manifest_path: object,
) -> OptionalDependencyExtractionResult:
    """
    Extract optional dependencies from a package.json manifest.

    Supported manifest:
      - package.json

    The operation is strictly read-only.

    It does not:
      - install packages
      - modify package.json
      - modify lockfiles
      - execute package-manager commands
      - execute project code
    """
    path, status = _resolve_manifest_path(manifest_path)

    if path is None:
        return OptionalDependencyExtractionResult(
            manifest_path=None,
            dependencies=(),
            extracted=False,
            status=status,
        )

    if path.name.lower() != "package.json":
        return OptionalDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_MANIFEST",
        )

    data, read_status = _read_json_manifest(path)

    if data is None:
        return OptionalDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status=read_status,
        )

    dependencies, extraction_status = _extract_optional_dependencies(data)

    return OptionalDependencyExtractionResult(
        manifest_path=path,
        dependencies=dependencies,
        extracted=extraction_status in {
            "EXTRACTED",
            "NO_OPTIONAL_DEPENDENCIES",
        },
        status=extraction_status,
    )
