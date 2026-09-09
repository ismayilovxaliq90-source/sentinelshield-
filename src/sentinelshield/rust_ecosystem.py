from dataclasses import dataclass
from pathlib import Path
import os

IGNORED = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache", "build",
    "dist", "target", ".next", ".nuxt", ".turbo"
}

MARKERS = {
    "Cargo.toml": "CARGO_TOML",
    "Cargo.lock": "CARGO_LOCK",
    "rust-toolchain": "RUST_TOOLCHAIN",
    "rust-toolchain.toml": "RUST_TOOLCHAIN_TOML",
}
SOURCE_EXTENSIONS = {".rs"}


@dataclass(frozen=True)
class RustEcosystemResult:
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


def detect_rust_ecosystem(project_root):
    root, error = _validate_root(project_root)
    if error:
        return RustEcosystemResult(
            False, str(project_root), [], [], "NONE", error
        )

    found = []
    source_found = False

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

            if path.suffix.lower() in SOURCE_EXTENSIONS:
                source_found = True

    found.sort(key=lambda item: item[0])

    markers = [item[0] for item in found]
    marker_types = [item[1] for item in found]

    if found:
        return RustEcosystemResult(
            True, str(root), markers, marker_types,
            "HIGH", "RUST_ECOSYSTEM_DETECTED"
        )

    if source_found:
        return RustEcosystemResult(
            True, str(root), [], ["RUST_SOURCE"],
            "MEDIUM", "RUST_SOURCE_DETECTED"
        )

    return RustEcosystemResult(
        False, str(root), [], [], "NONE",
        "RUST_ECOSYSTEM_NOT_DETECTED"
    )
