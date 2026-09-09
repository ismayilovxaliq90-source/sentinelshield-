from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class LockfileParserSelectionResult:
    lockfile_path: Optional[Path]
    parser: Optional[str]
    lockfile_type: Optional[str]
    supported: bool
    status: str


# Parser selection is based only on the lockfile filename.
# The selected parser identifies the serialization/text format;
# it does not parse or modify the lockfile.
LOCKFILE_PARSER_MAP = {
    "package-lock.json": ("json", "npm"),
    "yarn.lock": ("yarn", "yarn"),
    "pnpm-lock.yaml": ("yaml", "pnpm"),
    "poetry.lock": ("toml", "poetry"),
    "pipfile.lock": ("json", "pipenv"),
    "cargo.lock": ("toml", "cargo"),
    "composer.lock": ("json", "composer"),
    "go.sum": ("lines", "go"),
}


def _resolve_lockfile_path(
    lockfile_path: object,
) -> tuple[Optional[Path], str]:
    if lockfile_path is None:
        return None, "PATH_IS_NONE"

    if not isinstance(lockfile_path, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(lockfile_path).strip()

    if not raw:
        return None, "PATH_IS_EMPTY"

    if "\x00" in raw:
        return None, "NULL_CHARACTER_NOT_ALLOWED"

    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except FileNotFoundError:
        return None, "PATH_NOT_FOUND"
    except OSError:
        return None, "PATH_RESOLUTION_ERROR"

    try:
        if not path.is_file():
            return None, "NOT_A_FILE"
    except OSError:
        return None, "FILESYSTEM_ERROR"

    return path, "VALID"


def select_lockfile_parser(
    lockfile_path: object,
) -> LockfileParserSelectionResult:
    """
    Select the parser required for a supported lockfile.

    This function performs read-only path validation and filename-based
    parser selection. It deliberately does not read, parse, or modify
    the lockfile contents.
    """
    path, status = _resolve_lockfile_path(lockfile_path)

    if path is None:
        return LockfileParserSelectionResult(
            lockfile_path=None,
            parser=None,
            lockfile_type=None,
            supported=False,
            status=status,
        )

    filename = path.name.lower()
    parser_info = LOCKFILE_PARSER_MAP.get(filename)

    if parser_info is None:
        return LockfileParserSelectionResult(
            lockfile_path=path,
            parser=None,
            lockfile_type=None,
            supported=False,
            status="UNSUPPORTED_LOCKFILE",
        )

    parser, lockfile_type = parser_info

    return LockfileParserSelectionResult(
        lockfile_path=path,
        parser=parser,
        lockfile_type=lockfile_type,
        supported=True,
        status="SELECTED",
    )
