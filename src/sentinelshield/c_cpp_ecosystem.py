from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target", "vendor",
    "bin", "obj",
    ".next", ".nuxt", ".turbo",
    "cmake-build-debug", "cmake-build-release",
    "cmake-build-relwithdebinfo", "cmake-build-minsizerel",
}

MARKER_NAMES = {
    "CMakeLists.txt": "CMAKE",
    "Makefile": "MAKEFILE",
    "makefile": "MAKEFILE",
    "GNUmakefile": "GNUMAKEFILE",
    "meson.build": "MESON",
    "configure.ac": "AUTOCONF",
    "configure.in": "AUTOCONF",
    "conanfile.py": "CONAN",
    "conanfile.txt": "CONAN",
    "vcpkg.json": "VCPKG",
}

MARKER_SUFFIXES = {
    ".vcxproj": "VCXPROJ",
    ".sln": "SLN",
}

SOURCE_EXTENSIONS = {
    ".c", ".h",
    ".cc", ".hh",
    ".cpp", ".hpp",
    ".cxx", ".hxx",
    ".ixx",
}

STRONG_MARKER_TYPES = {
    "CMAKE",
    "MAKEFILE",
    "GNUMAKEFILE",
    "MESON",
    "AUTOCONF",
    "CONAN",
    "VCPKG",
    "VCXPROJ",
}

SOLUTION_MARKER_TYPES = {"SLN"}

@dataclass(frozen=True)
class CCppEcosystemResult:
    detected: bool
    root: Optional[Path]
    markers: list[str]
    marker_types: dict[str, str]
    confidence: str
    reason: str


def _invalid(reason: str) -> CCppEcosystemResult:
    return CCppEcosystemResult(
        detected=False,
        root=None,
        markers=[],
        marker_types={},
        confidence="NONE",
        reason=reason,
    )


def detect_c_cpp_ecosystem(path) -> CCppEcosystemResult:
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

                    # Ignore generated CMake build directories by pattern.
                    if entry.name.startswith("cmake-build-"):
                        continue

                    scan(entry)
                    continue

                if not entry.is_file():
                    continue

                name = entry.name
                marker_type = MARKER_NAMES.get(name)

                if marker_type is None:
                    for suffix, kind in MARKER_SUFFIXES.items():
                        if name.lower().endswith(suffix):
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

    found.sort(key=lambda item: item[0])

    markers = [relative for relative, _ in found]
    marker_types = {relative: kind for relative, kind in found}
    types = {kind for _, kind in found}

    if not found:
        return CCppEcosystemResult(
            detected=False,
            root=root,
            markers=[],
            marker_types={},
            confidence="NONE",
            reason="C_CPP_ECOSYSTEM_NOT_DETECTED",
        )

    if types & STRONG_MARKER_TYPES:
        confidence = "HIGH"
        reason = "C_CPP_BUILD_SYSTEM_OR_PROJECT_DETECTED"
    elif types & SOLUTION_MARKER_TYPES:
        confidence = "MEDIUM"
        reason = "C_CPP_SOLUTION_DETECTED"
    else:
        confidence = "MEDIUM"
        reason = "C_CPP_SOURCE_DETECTED"

    return CCppEcosystemResult(
        detected=True,
        root=root,
        markers=markers,
        marker_types=marker_types,
        confidence=confidence,
        reason=reason,
    )
