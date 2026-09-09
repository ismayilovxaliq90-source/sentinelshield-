from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target", ".next", ".nuxt",
}

VERSION_FILES = {
    ".python-version": "python",
    ".nvmrc": "node",
    ".node-version": "node",
    ".java-version": "java",
    ".ruby-version": "ruby",
    ".go-version": "go",
    "rust-toolchain": "rust",
    "rust-toolchain.toml": "rust",
    ".tool-versions": "asdf",
}


@dataclass(frozen=True)
class RuntimeVersion:
    runtime: str
    version: str
    source: Path


@dataclass(frozen=True)
class RuntimeVersionResult:
    found: bool
    root: Path | None
    versions: tuple[RuntimeVersion, ...]
    runtimes: tuple[str, ...]
    reason: str


def _clean_version(value: str) -> str | None:
    value = value.strip()

    if not value:
        return None

    if "\x00" in value:
        return None

    # Keep only the first meaningful line.
    value = value.splitlines()[0].strip()

    for prefix in ("python-", "node-", "java-", "ruby-", "go", "rust-"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):].strip()

    if value.startswith(("v", "V")):
        value = value[1:]

    return value or None


def _parse_version_file(path: Path, runtime: str) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None

    if runtime == "asdf":
        for line in text.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) >= 2:
                return _clean_version(parts[1])

        return None

    if runtime == "rust":
        for line in text.splitlines():
            line = line.strip()

            if line.startswith("channel"):
                if "=" in line:
                    value = line.split("=", 1)[1].strip()
                    value = value.strip("\"'")
                    return _clean_version(value)

        return _clean_version(text)

    return _clean_version(text)


def detect_runtime_versions(value: Any) -> RuntimeVersionResult:
    if value is None:
        return RuntimeVersionResult(
            False, None, (), (), "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return RuntimeVersionResult(
            False, None, (), (), "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return RuntimeVersionResult(
                False, None, (), (), "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return RuntimeVersionResult(
            False, None, (), (), "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return RuntimeVersionResult(
            False, None, (), (), "PATH_RESOLUTION_FAILED",
        )

    if not root.exists():
        return RuntimeVersionResult(
            False, root, (), (), "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return RuntimeVersionResult(
            False, root, (), (), "PATH_IS_NOT_DIRECTORY"
        )

    results: list[RuntimeVersion] = []
    stack = [root]

    while stack:
        current = stack.pop()

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError:
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name in IGNORED_DIRECTORIES:
                        continue
                    stack.append(entry)
                    continue

                if not entry.is_file():
                    continue

                runtime = VERSION_FILES.get(entry.name.lower())
                if runtime is None:
                    continue

                version = _parse_version_file(entry, runtime)

                if version is not None:
                    results.append(
                        RuntimeVersion(
                            runtime=runtime,
                            version=version,
                            source=entry.relative_to(root),
                        )
                    )

            except (OSError, ValueError):
                continue

    results.sort(
        key=lambda item: (
            item.runtime,
            item.version,
            item.source.as_posix(),
        )
    )

    runtimes = tuple(sorted({item.runtime for item in results}))

    return RuntimeVersionResult(
        bool(results),
        root,
        tuple(results),
        runtimes,
        "RUNTIME_VERSIONS_DETECTED"
        if results
        else "RUNTIME_VERSIONS_NOT_DETECTED",
    )


def detect_runtime_version(
    value: Any,
) -> RuntimeVersionResult:
    return detect_runtime_versions(value)
