from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class DevelopmentDependency:
    name: str
    version: Optional[str]
    source: Optional[str] = None


@dataclass(frozen=True)
class DevelopmentDependencyExtractionResult:
    manifest_path: Optional[Path]
    dependencies: tuple[DevelopmentDependency, ...]
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


def _finalize(
    dependencies: list[DevelopmentDependency],
) -> tuple[tuple[DevelopmentDependency, ...], str]:
    unique: dict[
        tuple[str, Optional[str], Optional[str]],
        DevelopmentDependency,
    ] = {}

    for dependency in dependencies:
        key = (
            dependency.name,
            dependency.version,
            dependency.source,
        )
        unique[key] = dependency

    ordered = sorted(
        unique.values(),
        key=lambda dependency: (
            dependency.name.lower(),
            dependency.version or "",
            dependency.source or "",
        ),
    )

    return tuple(ordered), "EXTRACTED"


def _extract_json_development_dependencies(
    path: Path,
) -> tuple[tuple[DevelopmentDependency, ...], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError):
        return (), "READ_ERROR"
    except json.JSONDecodeError:
        return (), "PARSE_ERROR"

    if not isinstance(data, dict):
        return (), "INVALID_MANIFEST_STRUCTURE"

    dependencies: list[DevelopmentDependency] = []

    filename = path.name.lower()

    if filename == "package.json":
        section_name = "devDependencies"

    elif filename == "composer.json":
        section_name = "require-dev"

    else:
        return (), "UNSUPPORTED_MANIFEST"

    section = data.get(section_name)

    if section is None:
        return (), "NO_DEVELOPMENT_DEPENDENCIES"

    if not isinstance(section, dict):
        return (), "INVALID_DEPENDENCY_SECTION"

    for name, version in section.items():
        if not isinstance(name, str) or not name.strip():
            return (), "INVALID_DEPENDENCY_NAME"

        if not isinstance(version, str):
            return (), "INVALID_DEPENDENCY_VERSION"

        dependencies.append(
            DevelopmentDependency(
                name=name,
                version=version,
                source=section_name,
            )
        )

    return _finalize(dependencies)


def _extract_requirements_development_dependencies(
    path: Path,
) -> tuple[tuple[DevelopmentDependency, ...], str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return (), "READ_ERROR"

    dependencies: list[DevelopmentDependency] = []

    requirement_pattern = re.compile(
        r"^\s*"
        r"([A-Za-z0-9][A-Za-z0-9_.-]*)"
        r"\s*"
        r"((?:===|==|!=|<=|>=|~=|<|>)\s*[^;\s]+)?"
        r"\s*(?:;.*)?$"
    )

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        match = requirement_pattern.match(line)

        if match is None:
            continue

        name = match.group(1)
        version = match.group(2)

        if version is not None:
            version = version.strip()

        dependencies.append(
            DevelopmentDependency(
                name=name,
                version=version,
                source="requirements.txt",
            )
        )

    return _finalize(dependencies)


def _extract_pipfile_development_dependencies(
    path: Path,
) -> tuple[tuple[DevelopmentDependency, ...], str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return (), "READ_ERROR"

    dependencies: list[DevelopmentDependency] = []

    in_dev_section = False

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line == "[dev-packages]":
            in_dev_section = True
            continue

        if line.startswith("[") and line.endswith("]"):
            if line != "[dev-packages]":
                in_dev_section = False
            continue

        if not in_dev_section:
            continue

        if "=" not in line:
            continue

        name, value = line.split("=", 1)

        name = name.strip()
        value = value.strip()

        if not name:
            return (), "INVALID_DEPENDENCY_NAME"

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]

        dependencies.append(
            DevelopmentDependency(
                name=name,
                version=value or None,
                source="Pipfile",
            )
        )

    if not dependencies:
        return (), "NO_DEVELOPMENT_DEPENDENCIES"

    return _finalize(dependencies)


def extract_development_dependencies(
    manifest_path: object,
) -> DevelopmentDependencyExtractionResult:
    """
    Extract development-only dependencies from supported manifests.

    Supported development dependency sources:
      - package.json -> devDependencies
      - composer.json -> require-dev
      - Pipfile -> [dev-packages]
      - requirements.txt -> requirements entries

    The operation is strictly read-only.
    It never installs packages, modifies files, regenerates lockfiles,
    or executes project commands.
    """
    path, status = _resolve_manifest_path(manifest_path)

    if path is None:
        return DevelopmentDependencyExtractionResult(
            manifest_path=None,
            dependencies=(),
            extracted=False,
            status=status,
        )

    filename = path.name.lower()

    if filename in {"package.json", "composer.json"}:
        dependencies, extraction_status = (
            _extract_json_development_dependencies(path)
        )

    elif filename == "pipfile":
        dependencies, extraction_status = (
            _extract_pipfile_development_dependencies(path)
        )

    elif filename == "requirements.txt":
        dependencies, extraction_status = (
            _extract_requirements_development_dependencies(path)
        )

    else:
        return DevelopmentDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_MANIFEST",
        )

    return DevelopmentDependencyExtractionResult(
        manifest_path=path,
        dependencies=dependencies,
        extracted=extraction_status == "EXTRACTED",
        status=extraction_status,
    )
