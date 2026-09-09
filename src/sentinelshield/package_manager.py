from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target", "vendor",
    "bin", "obj", ".bundle",
    ".next", ".nuxt", ".turbo",
    "cmake-build-debug", "cmake-build-release",
    "cmake-build-relwithdebinfo", "cmake-build-minsizerel",
}


MARKERS = {
    "requirements.txt": ("Python", "pip"),
    "pyproject.toml": ("Python", "pip"),
    "poetry.lock": ("Python", "Poetry"),
    "Pipfile": ("Python", "Pipenv"),
    "Pipfile.lock": ("Python", "Pipenv"),
    "uv.lock": ("Python", "uv"),

    "package-lock.json": ("Node.js", "npm"),
    "npm-shrinkwrap.json": ("Node.js", "npm"),
    "yarn.lock": ("Node.js", "Yarn"),
    "pnpm-lock.yaml": ("Node.js", "pnpm"),
    "bun.lock": ("Node.js", "Bun"),
    "bun.lockb": ("Node.js", "Bun"),

    "pom.xml": ("Java", "Maven"),
    "mvnw": ("Java", "Maven"),
    "build.gradle": ("Java", "Gradle"),
    "build.gradle.kts": ("Java", "Gradle"),
    "gradlew": ("Java", "Gradle"),

    "go.mod": ("Go", "Go Modules"),
    "go.sum": ("Go", "Go Modules"),

    "Cargo.toml": ("Rust", "Cargo"),
    "Cargo.lock": ("Rust", "Cargo"),

    "composer.json": ("PHP", "Composer"),
    "composer.lock": ("PHP", "Composer"),

    "Gemfile": ("Ruby", "Bundler"),
    "Gemfile.lock": ("Ruby", "Bundler"),

    ".csproj": (".NET", "NuGet"),
    ".fsproj": (".NET", "NuGet"),
    ".vbproj": (".NET", "NuGet"),
    "packages.config": (".NET", "NuGet"),

    "conanfile.py": ("C/C++", "Conan"),
    "conanfile.txt": ("C/C++", "Conan"),
    "vcpkg.json": ("C/C++", "vcpkg"),
}


STRONG_MARKERS = {
    "requirements.txt",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",

    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",

    "pom.xml",
    "mvnw",
    "build.gradle",
    "build.gradle.kts",
    "gradlew",

    "go.mod",

    "Cargo.toml",

    "composer.json",

    "Gemfile",

    ".csproj",
    ".fsproj",
    ".vbproj",
    "packages.config",

    "conanfile.py",
    "conanfile.txt",
    "vcpkg.json",
}


@dataclass(frozen=True)
class PackageManagerResult:
    detected: bool
    root: Optional[Path]
    package_managers: list[str]
    manager_count: int
    ecosystems: list[str]
    markers: list[str]
    marker_types: dict[str, str]
    confidence: str
    reason: str


def _invalid(reason: str) -> PackageManagerResult:
    return PackageManagerResult(
        detected=False,
        root=None,
        package_managers=[],
        manager_count=0,
        ecosystems=[],
        markers=[],
        marker_types={},
        confidence="NONE",
        reason=reason,
    )


def _match_marker(name: str):
    if name in MARKERS:
        return MARKERS[name]

    lowered = name.lower()

    for marker, value in MARKERS.items():
        if marker.startswith(".") and lowered.endswith(marker.lower()):
            return value

    return None


def detect_package_managers(path) -> PackageManagerResult:
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

    found = []

    def scan(directory: Path) -> None:
        try:
            entries = sorted(
                directory.iterdir(),
                key=lambda item: item.name,
            )
        except OSError:
            return

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name in IGNORED_DIRECTORIES:
                        continue

                    if entry.name.startswith("cmake-build-"):
                        continue

                    scan(entry)
                    continue

                if not entry.is_file():
                    continue

                matched = _match_marker(entry.name)

                if matched is None:
                    continue

                ecosystem, manager = matched
                relative = entry.relative_to(root).as_posix()

                found.append(
                    (
                        relative,
                        ecosystem,
                        manager,
                        entry.name,
                    )
                )

            except (OSError, ValueError):
                continue

    scan(root)

    found.sort(key=lambda item: item[0])

    if not found:
        return PackageManagerResult(
            detected=False,
            root=root,
            package_managers=[],
            manager_count=0,
            ecosystems=[],
            markers=[],
            marker_types={},
            confidence="NONE",
            reason="PACKAGE_MANAGER_NOT_DETECTED",
        )

    managers = sorted(
        {manager for _, _, manager, _ in found}
    )

    ecosystems = sorted(
        {ecosystem for _, ecosystem, _, _ in found}
    )

    markers = [
        relative
        for relative, _, _, _ in found
    ]

    marker_types = {
        relative: f"{ecosystem}:{manager}"
        for relative, ecosystem, manager, _ in found
    }

    strong_hits = set()

    for _, _, manager, marker_name in found:
        if marker_name in STRONG_MARKERS:
            strong_hits.add(manager)
            continue

        lowered = marker_name.lower()

        for strong_marker in STRONG_MARKERS:
            if (
                strong_marker.startswith(".")
                and lowered.endswith(strong_marker.lower())
            ):
                strong_hits.add(manager)
                break

    if len(strong_hits) == 1:
        confidence = "HIGH"
        reason = "PACKAGE_MANAGER_DETECTED"
    elif len(strong_hits) > 1:
        confidence = "MEDIUM"
        reason = "MULTIPLE_PACKAGE_MANAGERS_DETECTED"
    else:
        confidence = "MEDIUM"
        reason = "PACKAGE_MANAGER_MARKER_DETECTED"

    return PackageManagerResult(
        detected=True,
        root=root,
        package_managers=managers,
        manager_count=len(managers),
        ecosystems=ecosystems,
        markers=markers,
        marker_types=marker_types,
        confidence=confidence,
        reason=reason,
    )
