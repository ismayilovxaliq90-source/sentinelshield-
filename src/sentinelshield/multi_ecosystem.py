from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
    "target",
    "vendor",
    "bin",
    "obj",
    ".bundle",
    ".next",
    ".nuxt",
    ".turbo",
    "cmake-build-debug",
    "cmake-build-release",
    "cmake-build-relwithdebinfo",
    "cmake-build-minsizerel",
}


# Exact filename markers.
EXACT_MARKERS = {
    "Python": {
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "setup.py",
        "setup.cfg",
        "tox.ini",
        "pytest.ini",
        "poetry.lock",
        "uv.lock",
    },
    "Node.js": {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        ".nvmrc",
        ".node-version",
    },
    "Java": {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradlew",
        "mvnw",
        "gradle.properties",
    },
    "Go": {
        "go.mod",
        "go.sum",
        "go.work",
        "go.work.sum",
    },
    "Rust": {
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain",
        "rust-toolchain.toml",
    },
    "PHP": {
        "composer.json",
        "composer.lock",
        "phpunit.xml",
        "phpunit.xml.dist",
    },
    "Ruby": {
        "Gemfile",
        "Gemfile.lock",
        ".ruby-version",
        ".ruby-gemset",
        "Rakefile",
    },
    ".NET": {
        "global.json",
        "Directory.Build.props",
        "Directory.Build.targets",
        "packages.config",
    },
    "C/C++": {
        "CMakeLists.txt",
        "Makefile",
        "makefile",
        "GNUmakefile",
        "meson.build",
        "configure.ac",
        "configure.in",
        "conanfile.py",
        "conanfile.txt",
        "vcpkg.json",
    },
}


SUFFIX_MARKERS = {
    ".NET": {
        ".csproj",
        ".fsproj",
        ".vbproj",
        ".sln",
        ".slnx",
    },
    "C/C++": {
        ".vcxproj",
    },
}


SOURCE_EXTENSIONS = {
    "Python": {".py"},
    "Node.js": {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
    },
    "Java": {".java"},
    "Go": {".go"},
    "Rust": {".rs"},
    "PHP": {
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".php8",
        ".phtml",
    },
    "Ruby": {
        ".rb",
        ".rake",
        ".gemspec",
    },
    ".NET": {
        ".cs",
        ".fs",
        ".vb",
    },
    "C/C++": {
        ".c",
        ".h",
        ".cc",
        ".hh",
        ".cpp",
        ".hpp",
        ".cxx",
        ".hxx",
        ".ixx",
    },
}


@dataclass(frozen=True)
class MultiEcosystemResult:
    detected: bool
    root: Optional[Path]
    ecosystems: list[str]
    ecosystem_count: int
    markers: list[str]
    marker_types: dict[str, str]
    confidence: str
    reason: str


def _invalid(reason: str) -> MultiEcosystemResult:
    return MultiEcosystemResult(
        detected=False,
        root=None,
        ecosystems=[],
        ecosystem_count=0,
        markers=[],
        marker_types={},
        confidence="NONE",
        reason=reason,
    )


def _marker_type(ecosystem: str, name: str) -> Optional[str]:
    if name in EXACT_MARKERS.get(ecosystem, set()):
        return f"{ecosystem.upper().replace('.', '').replace('/', '_').replace('+', 'P')}_MARKER"

    lowered = name.lower()

    for suffix in SUFFIX_MARKERS.get(ecosystem, set()):
        if lowered.endswith(suffix.lower()):
            return f"{ecosystem.upper().replace('.', '').replace('/', '_').replace('+', 'P')}_PROJECT"

    return None


def detect_multi_ecosystem(path) -> MultiEcosystemResult:
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
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
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

                name = entry.name
                relative = entry.relative_to(root).as_posix()

                detected_marker = False

                for ecosystem in EXACT_MARKERS:
                    marker_type = _marker_type(ecosystem, name)

                    if marker_type is not None:
                        found.append(
                            (relative, ecosystem, marker_type)
                        )
                        detected_marker = True
                        break

                if detected_marker:
                    continue

                for ecosystem, suffixes in SUFFIX_MARKERS.items():
                    if any(
                        name.lower().endswith(suffix.lower())
                        for suffix in suffixes
                    ):
                        marker_type = _marker_type(ecosystem, name)
                        found.append(
                            (relative, ecosystem, marker_type)
                        )
                        detected_marker = True
                        break

                if detected_marker:
                    continue

                extension = entry.suffix.lower()

                for ecosystem, extensions in SOURCE_EXTENSIONS.items():
                    if extension in extensions:
                        found.append(
                            (relative, ecosystem, "SOURCE")
                        )
                        break

            except (OSError, ValueError):
                continue

    scan(root)

    found.sort(key=lambda item: item[0])

    ecosystems = sorted(
        {ecosystem for _, ecosystem, _ in found}
    )

    markers = [
        relative
        for relative, _, _ in found
    ]

    marker_types = {
        relative: marker_type
        for relative, _, marker_type in found
    }

    ecosystem_count = len(ecosystems)

    if ecosystem_count == 0:
        return MultiEcosystemResult(
            detected=False,
            root=root,
            ecosystems=[],
            ecosystem_count=0,
            markers=[],
            marker_types={},
            confidence="NONE",
            reason="MULTI_ECOSYSTEM_NOT_DETECTED",
        )

    if ecosystem_count == 1:
        confidence = "HIGH"
        reason = "SINGLE_ECOSYSTEM_DETECTED"
    else:
        confidence = "HIGH"
        reason = "MULTIPLE_ECOSYSTEMS_DETECTED"

    return MultiEcosystemResult(
        detected=True,
        root=root,
        ecosystems=ecosystems,
        ecosystem_count=ecosystem_count,
        markers=markers,
        marker_types=marker_types,
        confidence=confidence,
        reason=reason,
    )
