from dataclasses import dataclass
from pathlib import Path
import os

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache", "build",
    "dist", "target", "vendor", ".next", ".nuxt", ".turbo"
}

MARKERS = {
    "composer.json": "COMPOSER_JSON",
    "composer.lock": "COMPOSER_LOCK",
    "phpunit.xml": "PHPUNIT_XML",
    "phpunit.xml.dist": "PHPUNIT_XML_DIST",
}
PHP_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml"}


@dataclass(frozen=True)
class PHPEcosystemResult:
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


def detect_php_ecosystem(project_root):
    root, error = _validate_root(project_root)
    if error:
        return PHPEcosystemResult(
            False, str(project_root), [], [], "NONE", error
        )

    found = []
    php_source_found = False

    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)

        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in IGNORED
            and not (current_path / d).is_symlink()
        )

        for name in sorted(files):
            path = current_path / name

            if path.is_symlink():
                continue

            relative = path.relative_to(root).as_posix()

            if name in MARKERS:
                found.append((relative, MARKERS[name]))

            if path.suffix.lower() in PHP_EXTENSIONS:
                php_source_found = True

    found.sort(key=lambda item: item[0])
    markers = [item[0] for item in found]
    marker_types = [item[1] for item in found]

    strong = {
        "COMPOSER_JSON",
        "COMPOSER_LOCK",
    }

    if any(kind in strong for kind in marker_types):
        return PHPEcosystemResult(
            True, str(root), markers, marker_types,
            "HIGH", "PHP_ECOSYSTEM_DETECTED"
        )

    if found or php_source_found:
        if php_source_found and not found:
            marker_types = ["PHP_SOURCE"]
            markers = []
        return PHPEcosystemResult(
            True, str(root), markers, marker_types,
            "MEDIUM", "PHP_ECOSYSTEM_DETECTED"
        )

    return PHPEcosystemResult(
        False, str(root), [], [], "NONE",
        "PHP_ECOSYSTEM_NOT_DETECTED"
    )
