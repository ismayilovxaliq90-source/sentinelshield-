from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import json
import re
import urllib.parse


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


@dataclass(frozen=True)
class PackageManagerVersion:
    manager: str
    version: str
    source: str


@dataclass(frozen=True)
class PackageManagerVersionResult:
    detected: bool
    root: Optional[Path]
    versions: list[PackageManagerVersion]
    manager_count: int
    managers: list[str]
    confidence: str
    reason: str


def _invalid(reason: str) -> PackageManagerVersionResult:
    return PackageManagerVersionResult(
        detected=False,
        root=None,
        versions=[],
        manager_count=0,
        managers=[],
        confidence="NONE",
        reason=reason,
    )


VERSION_RE = re.compile(
    r"(?<![0-9])"
    r"v?"
    r"([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
    r"(?![0-9])"
)


def _extract_version(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None

    match = VERSION_RE.search(value.strip())

    if match is None:
        return None

    return match.group(1)


def _add_version(found, manager: str, version: str, source: str) -> None:
    if version:
        found.append(
            PackageManagerVersion(
                manager=manager,
                version=version,
                source=source,
            )
        )


def _parse_package_json(path: Path, relative: str, found) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return

    if not isinstance(data, dict):
        return

    package_manager = data.get("packageManager")

    if isinstance(package_manager, str):
        match = re.match(
            r"^\s*(npm|yarn|pnpm|bun)@(.+?)\s*$",
            package_manager,
            re.IGNORECASE,
        )

        if match:
            manager = match.group(1).lower()
            version = _extract_version(match.group(2))

            if version:
                _add_version(
                    found,
                    manager,
                    version,
                    f"{relative}:packageManager",
                )

    engines = data.get("engines")

    if isinstance(engines, dict):
        for key in ("npm", "yarn", "pnpm", "bun"):
            value = engines.get(key)

            if not isinstance(value, str):
                continue

            version = _extract_version(value)

            if version:
                _add_version(
                    found,
                    key,
                    version,
                    f"{relative}:engines.{key}",
                )


def _parse_poetry(path: Path, relative: str, found) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return

    patterns = [
        r'(?im)^\s*poetry\s*=\s*["\']([^"\']+)["\']',
        r'(?im)^\s*poetry\s*=\s*\{[^}]*version\s*=\s*["\']([^"\']+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, text)

        if match:
            version = _extract_version(match.group(1))

            if version:
                _add_version(
                    found,
                    "Poetry",
                    version,
                    f"{relative}:poetry",
                )
                return


def _parse_maven_wrapper(
    path: Path,
    relative: str,
    found,
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return

    match = re.search(
        r"(?im)^\s*distributionUrl\s*=\s*(\S+)\s*$",
        text,
    )

    if not match:
        return

    url = match.group(1).strip()

    try:
        url = urllib.parse.unquote(url)
    except Exception:
        pass

    match = re.search(
        r"apache-maven-"
        r"([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
        r"-(?:bin|src)\.zip",
        url,
        re.IGNORECASE,
    )

    if not match:
        match = re.search(
            r"/([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)/"
            r"apache-maven-[^/]+\.zip",
            url,
            re.IGNORECASE,
        )

    if match:
        _add_version(
            found,
            "Maven",
            match.group(1),
            f"{relative}:distributionUrl",
        )


def _parse_gradle_wrapper(
    path: Path,
    relative: str,
    found,
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return

    match = re.search(
        r"(?im)^\s*distributionUrl\s*=\s*(\S+)\s*$",
        text,
    )

    if not match:
        return

    url = match.group(1).strip()

    try:
        url = urllib.parse.unquote(url)
    except Exception:
        pass

    match = re.search(
        r"gradle-"
        r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
        r"-(?:bin|all|src)\.zip",
        url,
        re.IGNORECASE,
    )

    if match:
        _add_version(
            found,
            "Gradle",
            match.group(1),
            f"{relative}:distributionUrl",
        )


def _parse_bundler(path: Path, relative: str, found) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return

    match = re.search(
        r"(?ms)^\s*BUNDLED\s+WITH\s*\n"
        r"\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)\s*$",
        text,
    )

    if match:
        _add_version(
            found,
            "Bundler",
            match.group(1),
            f"{relative}:BUNDLED WITH",
        )


def detect_package_manager_versions(path) -> PackageManagerVersionResult:
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

                relative = entry.relative_to(root).as_posix()

                if entry.name == "package.json":
                    _parse_package_json(
                        entry,
                        relative,
                        found,
                    )

                elif entry.name == "pyproject.toml":
                    _parse_poetry(
                        entry,
                        relative,
                        found,
                    )

                elif entry.name == "maven-wrapper.properties":
                    if relative.startswith(".mvn/wrapper/"):
                        _parse_maven_wrapper(
                            entry,
                            relative,
                            found,
                        )

                elif entry.name == "gradle-wrapper.properties":
                    if (
                        relative.startswith("gradle/wrapper/")
                        or relative.startswith(".gradle/wrapper/")
                    ):
                        _parse_gradle_wrapper(
                            entry,
                            relative,
                            found,
                        )

                elif entry.name == "Gemfile.lock":
                    _parse_bundler(
                        entry,
                        relative,
                        found,
                    )

            except (OSError, ValueError):
                continue

    scan(root)

    found.sort(
        key=lambda item: (
            item.manager.lower(),
            item.version,
            item.source,
        )
    )

    unique = []
    seen = set()

    for item in found:
        key = (
            item.manager,
            item.version,
            item.source,
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    found = unique

    if not found:
        return PackageManagerVersionResult(
            detected=False,
            root=root,
            versions=[],
            manager_count=0,
            managers=[],
            confidence="NONE",
            reason="PACKAGE_MANAGER_VERSION_NOT_DETECTED",
        )

    managers = sorted(
        {item.manager for item in found},
        key=str.lower,
    )

    return PackageManagerVersionResult(
        detected=True,
        root=root,
        versions=found,
        manager_count=len(managers),
        managers=managers,
        confidence="HIGH",
        reason="PACKAGE_MANAGER_VERSION_DETECTED",
    )
