from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class TransitiveDependency:
    name: str
    version: Optional[str]
    parent: str
    source: Optional[str] = None


@dataclass(frozen=True)
class TransitiveDependencyExtractionResult:
    lockfile_path: Optional[Path]
    dependencies: tuple[TransitiveDependency, ...]
    extracted: bool
    status: str


def _resolve_lockfile_path(
    lockfile_path: object,
) -> tuple[Optional[Path], str]:
    if lockfile_path is None:
        return None, "PATH_IS_NONE"

    if not isinstance(lockfile_path, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(lockfile_path).strip()

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


def _npm_package_name(package_path: str) -> str:
    marker = "node_modules/"

    if marker not in package_path:
        return package_path

    tail = package_path.split(marker)[-1]

    if tail.startswith("@"):
        parts = tail.split("/")

        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"

    return tail.split("/", 1)[0]


def _npm_parent_from_package_path(
    package_path: str,
) -> Optional[str]:
    marker = "node_modules/"

    if marker not in package_path:
        return None

    parts = package_path.split(marker)

    if len(parts) < 3:
        return None

    # Example:
    # node_modules/express/node_modules/body-parser
    # -> parent = express
    #
    # Example:
    # node_modules/a/node_modules/b/node_modules/c
    # -> parent = a for b
    # -> parent = b for c
    parent_segment = parts[-2].rstrip("/")

    if not parent_segment:
        return None

    if parent_segment.startswith("@"):
        if len(parts) >= 4:
            scope = parts[-3].rstrip("/")

            if scope.startswith("@"):
                return f"{scope}/{parent_segment}"

    return parent_segment


def _extract_package_lock(
    path: Path,
) -> tuple[tuple[TransitiveDependency, ...], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError):
        return (), "READ_ERROR"
    except json.JSONDecodeError:
        return (), "PARSE_ERROR"

    if not isinstance(data, dict):
        return (), "INVALID_LOCKFILE_STRUCTURE"

    packages = data.get("packages")

    if packages is None:
        return (), "MISSING_PACKAGES_SECTION"

    if not isinstance(packages, dict):
        return (), "INVALID_PACKAGES_SECTION"

    dependencies: list[TransitiveDependency] = []

    for package_path, package_info in packages.items():
        if not isinstance(package_path, str):
            return (), "INVALID_PACKAGE_PATH"

        # The root package is not a transitive dependency.
        if package_path == "":
            continue

        # Only node_modules entries represent installed packages.
        if not package_path.startswith("node_modules/"):
            continue

        if not isinstance(package_info, dict):
            continue

        parent = _npm_parent_from_package_path(package_path)

        # A package directly under the root node_modules directory is
        # a direct dependency and must not be returned here.
        if parent is None:
            continue

        name = package_info.get("name")

        if not isinstance(name, str) or not name.strip():
            name = _npm_package_name(package_path)

        version = package_info.get("version")

        if version is not None and not isinstance(version, str):
            version = str(version)

        dependencies.append(
            TransitiveDependency(
                name=name,
                version=version,
                parent=parent,
                source="package-lock.json",
            )
        )

    return _finalize(dependencies)


def _yarn_parent_name(header: str) -> str:
    header = header.strip().strip('"').strip("'")

    first_selector = header.split(",", 1)[0].strip()
    first_selector = first_selector.strip('"').strip("'")

    if first_selector.startswith("@"):
        slash = first_selector.find("/")

        if slash == -1:
            return first_selector

        version_at = first_selector.find("@", slash)

        if version_at == -1:
            return first_selector

        return first_selector[:version_at]

    if "@" in first_selector:
        return first_selector.rsplit("@", 1)[0]

    return first_selector


def _extract_yarn_lock(
    path: Path,
) -> tuple[tuple[TransitiveDependency, ...], str]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (), "READ_ERROR"

    # Test fixtures and embedded lockfile text can contain common leading
    # indentation. Remove only that common indentation; preserve the
    # relative indentation that defines Yarn's structure.
    content = textwrap.dedent(content)

    lines = content.splitlines()

    dependencies: list[TransitiveDependency] = []

    current_parent: Optional[str] = None
    in_dependencies = False
    dependency_indent: Optional[int] = None

    for raw_line in lines:
        if not raw_line.strip():
            continue

        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip(" "))

        # Yarn package selector.
        if indent == 0 and stripped.endswith(":"):
            header = stripped[:-1].strip()

            if "@" in header:
                current_parent = _yarn_parent_name(header)
            else:
                current_parent = None

            in_dependencies = False
            dependency_indent = None
            continue

        if current_parent is None:
            continue

        if stripped == "dependencies:":
            in_dependencies = True
            dependency_indent = indent
            continue

        if not in_dependencies:
            continue

        # A line at the same or lower indentation closes the
        # dependencies section.
        if dependency_indent is not None and indent <= dependency_indent:
            in_dependencies = False
            dependency_indent = None
            continue

        match = re.match(
            r"^([^\s:]+)\s+(.+)$",
            stripped,
        )

        if match is None:
            continue

        name = match.group(1).strip('"').strip("'")
        version = match.group(2).strip().strip('"').strip("'")

        if not name:
            continue

        dependencies.append(
            TransitiveDependency(
                name=name,
                version=version,
                parent=current_parent,
                source="yarn.lock",
            )
        )

    return _finalize(dependencies)


def _pnpm_package_name(package_key: str) -> str:
    package_key = package_key.strip().strip("'").strip('"')

    if package_key.startswith("@"):
        slash = package_key.find("/")

        if slash == -1:
            return package_key

        version_at = package_key.find("@", slash)

        if version_at == -1:
            return package_key

        return package_key[:version_at]

    if "@" in package_key:
        return package_key.rsplit("@", 1)[0]

    return package_key


def _extract_pnpm_lock(
    path: Path,
) -> tuple[tuple[TransitiveDependency, ...], str]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (), "READ_ERROR"

    content = textwrap.dedent(content)
    lines = content.splitlines()

    dependencies: list[TransitiveDependency] = []

    in_snapshots = False
    current_parent: Optional[str] = None
    in_dependencies = False
    dependency_indent: Optional[int] = None

    for raw_line in lines:
        if not raw_line.strip():
            continue

        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if indent == 0 and stripped == "snapshots:":
            in_snapshots = True
            current_parent = None
            in_dependencies = False
            dependency_indent = None
            continue

        if not in_snapshots:
            continue

        # Another top-level YAML section ends snapshots.
        if indent == 0:
            in_snapshots = False
            current_parent = None
            in_dependencies = False
            dependency_indent = None
            continue

        # Snapshot package keys are two spaces below snapshots.
        if indent == 2 and stripped.endswith(":"):
            package_key = stripped[:-1].strip()
            current_parent = _pnpm_package_name(package_key)
            in_dependencies = False
            dependency_indent = None
            continue

        if current_parent is None:
            continue

        if indent == 4 and stripped == "dependencies:":
            in_dependencies = True
            dependency_indent = indent
            continue

        if not in_dependencies:
            continue

        if dependency_indent is not None and indent <= dependency_indent:
            in_dependencies = False
            dependency_indent = None
            continue

        if ":" not in stripped:
            continue

        name, version = stripped.split(":", 1)

        name = name.strip().strip("'").strip('"')
        version = version.strip().strip("'").strip('"')

        if not name:
            continue

        dependencies.append(
            TransitiveDependency(
                name=name,
                version=version,
                parent=current_parent,
                source="pnpm-lock.yaml",
            )
        )

    return _finalize(dependencies)


def _finalize(
    dependencies: list[TransitiveDependency],
) -> tuple[tuple[TransitiveDependency, ...], str]:
    unique: dict[
        tuple[str, Optional[str], str, Optional[str]],
        TransitiveDependency,
    ] = {}

    for dependency in dependencies:
        key = (
            dependency.name,
            dependency.version,
            dependency.parent,
            dependency.source,
        )
        unique[key] = dependency

    ordered = sorted(
        unique.values(),
        key=lambda dependency: (
            dependency.name.lower(),
            dependency.version or "",
            dependency.parent.lower(),
            dependency.source or "",
        ),
    )

    return tuple(ordered), "EXTRACTED"


def extract_transitive_dependencies(
    lockfile_path: object,
) -> TransitiveDependencyExtractionResult:
    """
    Extract transitive dependencies from supported lockfiles.

    Supported lockfiles:
      - package-lock.json
      - yarn.lock
      - pnpm-lock.yaml

    The operation is strictly read-only.
    """
    path, status = _resolve_lockfile_path(lockfile_path)

    if path is None:
        return TransitiveDependencyExtractionResult(
            lockfile_path=None,
            dependencies=(),
            extracted=False,
            status=status,
        )

    filename = path.name.lower()

    if filename == "package-lock.json":
        dependencies, extraction_status = _extract_package_lock(path)
    elif filename == "yarn.lock":
        dependencies, extraction_status = _extract_yarn_lock(path)
    elif filename == "pnpm-lock.yaml":
        dependencies, extraction_status = _extract_pnpm_lock(path)
    else:
        return TransitiveDependencyExtractionResult(
            lockfile_path=path,
            dependencies=(),
            extracted=False,
            status="UNSUPPORTED_LOCKFILE",
        )

    return TransitiveDependencyExtractionResult(
        lockfile_path=path,
        dependencies=dependencies,
        extracted=extraction_status == "EXTRACTED",
        status=extraction_status,
    )
