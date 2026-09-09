from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class DirectDependency:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str] = None


@dataclass(frozen=True)
class DirectDependencyExtractionResult:
    manifest_path: Optional[Path]
    dependencies: tuple[DirectDependency, ...]
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


def _extract_json_dependencies(
    path: Path,
) -> tuple[tuple[DirectDependency, ...], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError):
        return (), "READ_ERROR"
    except json.JSONDecodeError:
        return (), "PARSE_ERROR"

    if not isinstance(data, dict):
        return (), "INVALID_MANIFEST_STRUCTURE"

    dependencies: list[DirectDependency] = []

    sections = (
        ("dependencies", "production"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    )

    for section_name, dependency_type in sections:
        section = data.get(section_name)

        if section is None:
            continue

        if not isinstance(section, dict):
            return (), "INVALID_DEPENDENCY_SECTION"

        for name, version in section.items():
            if not isinstance(name, str) or not name.strip():
                return (), "INVALID_DEPENDENCY_NAME"

            if not isinstance(version, str):
                return (), "INVALID_DEPENDENCY_VERSION"

            dependencies.append(
                DirectDependency(
                    name=name,
                    version=version,
                    dependency_type=dependency_type,
                    source=section_name,
                )
            )

    dependencies.sort(
        key=lambda dependency: (
            dependency.name,
            dependency.dependency_type,
            dependency.version or "",
        )
    )

    return tuple(dependencies), "EXTRACTED"


def _extract_python_requirements(
    path: Path,
) -> tuple[tuple[DirectDependency, ...], str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return (), "READ_ERROR"

    dependencies: list[DirectDependency] = []

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

        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            continue

        match = requirement_pattern.match(line)

        if match is None:
            continue

        name = match.group(1)
        version = match.group(2)

        if version is not None:
            version = version.strip()

        dependencies.append(
            DirectDependency(
                name=name,
                version=version,
                dependency_type="production",
                source="requirements.txt",
            )
        )

    dependencies.sort(
        key=lambda dependency: (
            dependency.name.lower(),
            dependency.version or "",
        )
    )

    return tuple(dependencies), "EXTRACTED"


def extract_direct_dependencies(
    manifest_path: object,
) -> DirectDependencyExtractionResult:
    """
    Extract direct dependencies from a supported manifest.

    Supported input formats:
      - package.json
      - composer.json
      - requirements.txt

    The function is strictly read-only. It never installs packages,
    modifies files, regenerates lockfiles, or executes project commands.
    """
    path, status = _resolve_manifest_path(manifest_path)

    if path is None:
        return DirectDependencyExtractionResult(
            manifest_path=None,
            dependencies=(),
            extracted=False,
            status=status,
        )

    filename = path.name.lower()

    if filename in {"package.json", "composer.json"}:
        dependencies, extraction_status = _extract_json_dependencies(path)
    elif filename == "requirements.txt":
        dependencies, extraction_status = _extract_python_requirements(path)
    else:
        return DirectDependencyExtractionResult(
            manifest_path=path,
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_MANIFEST",
        )

    return DirectDependencyExtractionResult(
        manifest_path=path,
        dependencies=dependencies,
        extracted=extraction_status == "EXTRACTED",
        status=extraction_status,
    )
