from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


METADATA_FILES = (
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "*.csproj",
    "*.fsproj",
    "*.vbproj",
)


@dataclass(frozen=True)
class ProjectMetadataResult:
    found: bool
    root: Path | None
    project_name: str | None
    metadata_files: tuple[Path, ...]
    metadata_types: tuple[str, ...]
    metadata_count: int
    reason: str


def _metadata_type(path: Path) -> str:
    name = path.name.lower()

    if name == "pyproject.toml":
        return "python"
    if name == "package.json":
        return "node"
    if name == "cargo.toml":
        return "rust"
    if name == "go.mod":
        return "go"
    if name == "pom.xml":
        return "java"
    if name in {"build.gradle", "build.gradle.kts"}:
        return "gradle"
    if name == "composer.json":
        return "php"
    if name in {"gemfile"}:
        return "ruby"
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return "dotnet"

    return "unknown"


def collect_project_metadata(value: Any) -> ProjectMetadataResult:
    if value is None:
        return ProjectMetadataResult(
            False, None, None, (), (), 0, "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return ProjectMetadataResult(
            False, None, None, (), (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return ProjectMetadataResult(
                False, None, None, (), (), 0, "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return ProjectMetadataResult(
            False, None, None, (), (), 0,
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return ProjectMetadataResult(
            False, None, None, (), (), 0,
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return ProjectMetadataResult(
            False, root, None, (), (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return ProjectMetadataResult(
            False, root, None, (), (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    project_name = root.name or None
    found_files: set[Path] = set()

    for pattern in METADATA_FILES:
        try:
            for match in root.glob(pattern):
                if match.is_file() and not match.is_symlink():
                    found_files.add(match.relative_to(root))
        except (OSError, ValueError):
            continue

    metadata_files = tuple(
        sorted(found_files, key=lambda p: p.as_posix())
    )

    metadata_types = tuple(
        sorted({_metadata_type(path) for path in metadata_files})
    )

    return ProjectMetadataResult(
        True,
        root,
        project_name,
        metadata_files,
        metadata_types,
        len(metadata_files),
        "PROJECT_METADATA_COLLECTED",
    )
