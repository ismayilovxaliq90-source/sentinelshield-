from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target", "vendor", "bin", "obj",
    ".next", ".nuxt", ".turbo",
}

MARKER_TYPES = {
    ".csproj": "CSPROJ",
    ".fsproj": "FSPROJ",
    ".vbproj": "VBPROJ",
    ".sln": "SLN",
    ".slnx": "SLNX",
    "global.json": "GLOBAL_JSON",
    "Directory.Build.props": "DIRECTORY_BUILD_PROPS",
    "Directory.Build.targets": "DIRECTORY_BUILD_TARGETS",
    "packages.config": "PACKAGES_CONFIG",
}

STRONG_MARKER_TYPES = {
    "CSPROJ", "FSPROJ", "VBPROJ", "SLN", "SLNX"
}

SOURCE_EXTENSIONS = {".cs", ".fs", ".vb"}


@dataclass(frozen=True)
class DotNetEcosystemResult:
    detected: bool
    root: Optional[Path]
    markers: list[str]
    marker_types: dict[str, str]
    confidence: str
    reason: str


def _invalid(reason: str) -> DotNetEcosystemResult:
    return DotNetEcosystemResult(
        detected=False,
        root=None,
        markers=[],
        marker_types={},
        confidence="NONE",
        reason=reason,
    )


def detect_dotnet_ecosystem(path) -> DotNetEcosystemResult:
    if path is None:
        return _invalid("PATH_IS_NONE")

    if not isinstance(path, (str, Path)):
        return _invalid("UNSUPPORTED_PATH_TYPE")

    raw = str(path)

    if "\x00" in raw:
        return _invalid("NULL_CHARACTER_NOT_ALLOWED")

    if not raw.strip():
        return _invalid("PATH_IS_EMPTY")

    root = Path(raw).expanduser()

    try:
        root = root.resolve()
    except (OSError, RuntimeError):
        return _invalid("PATH_RESOLUTION_FAILED")

    try:
        if not root.exists():
            return _invalid("PATH_DOES_NOT_EXIST")
        if not root.is_dir():
            return _invalid("PATH_IS_NOT_DIRECTORY")
    except OSError:
        return _invalid("FILESYSTEM_ERROR")

    found: list[tuple[str, str]] = []

    def scan(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            return

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name in IGNORED_DIRECTORIES:
                        continue
                    scan(entry)
                    continue

                if not entry.is_file():
                    continue

                name = entry.name
                marker_type = None

                for suffix, kind in MARKER_TYPES.items():
                    if suffix.startswith("."):
                        if name.lower().endswith(suffix.lower()):
                            marker_type = kind
                            break
                    elif name == suffix:
                        marker_type = kind
                        break

                if marker_type is not None:
                    relative = entry.relative_to(root).as_posix()
                    found.append((relative, marker_type))
                    continue

                if entry.suffix.lower() in SOURCE_EXTENSIONS:
                    relative = entry.relative_to(root).as_posix()
                    found.append((relative, "SOURCE"))

            except (OSError, ValueError):
                continue

    scan(root)

    # Deterministic, case-sensitive lexical order.
    found.sort(key=lambda item: item[0])

    markers = [path for path, _ in found]
    marker_types = {path: kind for path, kind in found}

    if not found:
        return DotNetEcosystemResult(
            detected=False,
            root=root,
            markers=[],
            marker_types={},
            confidence="NONE",
            reason="DOTNET_ECOSYSTEM_NOT_DETECTED",
        )

    types = {kind for _, kind in found}

    if types & STRONG_MARKER_TYPES:
        confidence = "HIGH"
        reason = "DOTNET_PROJECT_OR_SOLUTION_DETECTED"
    else:
        confidence = "MEDIUM"
        reason = "DOTNET_MARKER_OR_SOURCE_DETECTED"

    return DotNetEcosystemResult(
        detected=True,
        root=root,
        markers=markers,
        marker_types=marker_types,
        confidence=confidence,
        reason=reason,
    )
