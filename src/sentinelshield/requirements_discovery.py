from dataclasses import dataclass
from pathlib import Path


IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache", "build",
    "dist", "target", ".tox", ".mypy_cache",
}


@dataclass(frozen=True)
class RequirementsDiscoveryResult:
    found: bool
    root: Path
    files: tuple[Path, ...]
    count: int
    reason: str


def discover_requirements_txt(root) -> RequirementsDiscoveryResult:
    if root is None:
        return RequirementsDiscoveryResult(
            False, Path("."), (), 0, "PATH_IS_NONE"
        )

    if isinstance(root, str):
        if not root.strip():
            return RequirementsDiscoveryResult(
                False, Path("."), (), 0, "PATH_IS_EMPTY"
            )
        if "\x00" in root:
            return RequirementsDiscoveryResult(
                False, Path("."), (), 0, "NULL_CHARACTER_NOT_ALLOWED"
            )
        root = Path(root)
    elif not isinstance(root, Path):
        return RequirementsDiscoveryResult(
            False, Path("."), (), 0, "UNSUPPORTED_PATH_TYPE"
        )

    if not root.exists():
        return RequirementsDiscoveryResult(
            False, root, (), 0, "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return RequirementsDiscoveryResult(
            False, root, (), 0, "PATH_IS_NOT_DIRECTORY"
        )

    found = []

    def scan(directory: Path):
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            return

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name in IGNORED_DIRS:
                        continue
                    scan(entry)
                    continue

                if entry.is_file() and entry.name == "requirements.txt":
                    found.append(entry.relative_to(root))
            except OSError:
                continue

    scan(root)

    files = tuple(sorted(found, key=lambda p: p.as_posix()))

    if not files:
        return RequirementsDiscoveryResult(
            False, root, (), 0, "REQUIREMENTS_TXT_NOT_FOUND"
        )

    return RequirementsDiscoveryResult(
        True, root, files, len(files), "REQUIREMENTS_TXT_DISCOVERED"
    )
