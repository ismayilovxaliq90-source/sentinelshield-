from dataclasses import dataclass
from pathlib import Path

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache", "build",
    "dist", "target", ".next", ".nuxt", ".turbo"
}

MARKERS = {
    "pom.xml": "POM_XML",
    "build.gradle": "BUILD_GRADLE",
    "build.gradle.kts": "BUILD_GRADLE_KTS",
    "settings.gradle": "SETTINGS_GRADLE",
    "settings.gradle.kts": "SETTINGS_GRADLE_KTS",
    "gradlew": "GRADLE_WRAPPER",
    "mvnw": "MAVEN_WRAPPER",
    "gradle.properties": "GRADLE_PROPERTIES",
}
JAVA_EXTENSIONS = {".java"}


@dataclass(frozen=True)
class JavaEcosystemResult:
    detected: bool
    root: str
    markers: list[str]
    marker_types: list[str]
    confidence: str
    reason: str


def _validate_root(value):
    if value is None:
        return None, "PATH_IS_NONE"
    if not isinstance(value, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"
    value = str(value).strip()
    if not value:
        return None, "PATH_IS_EMPTY"
    if "\x00" in value:
        return None, "NULL_CHARACTER_NOT_ALLOWED"
    root = Path(value).expanduser()
    try:
        root = root.resolve()
    except (OSError, RuntimeError):
        return None, "PATH_RESOLUTION_FAILED"
    if not root.exists():
        return None, "PATH_NOT_FOUND"
    if not root.is_dir():
        return None, "PATH_IS_NOT_DIRECTORY"
    return root, None


def detect_java_ecosystem(project_root):
    root, error = _validate_root(project_root)
    if error:
        return JavaEcosystemResult(
            False, str(project_root), [], [], "NONE", error
        )

    found = []
    source_found = False

    for current, dirs, files in __import__("os").walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in IGNORED
            and not (Path(current) / d).is_symlink()
        )

        current_path = Path(current)
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink():
                continue

            rel = path.relative_to(root).as_posix()

            if name in MARKERS:
                found.append((rel, MARKERS[name]))

            if path.suffix.lower() in JAVA_EXTENSIONS:
                source_found = True

    found.sort(key=lambda x: x[0])
    markers = [x[0] for x in found]
    marker_types = [x[1] for x in found]

    if found:
        confidence = "HIGH"
        reason = "JAVA_ECOSYSTEM_DETECTED"
    elif source_found:
        confidence = "MEDIUM"
        reason = "JAVA_SOURCE_DETECTED"
        marker_types = ["JAVA_SOURCE"]
    else:
        confidence = "NONE"
        reason = "JAVA_ECOSYSTEM_NOT_DETECTED"

    return JavaEcosystemResult(
        bool(found or source_found),
        str(root),
        markers,
        marker_types,
        confidence,
        reason,
    )
