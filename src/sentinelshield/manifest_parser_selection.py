from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class ManifestParserSelectionResult:
    manifest_path: Optional[Path]
    parser: Optional[str]
    manifest_type: Optional[str]
    supported: bool
    status: str


MANIFEST_PARSER_MAP = {
    "package.json": ("json", "node"),
    "cargo.toml": ("toml", "rust"),
    "composer.json": ("json", "php"),
    "pipfile": ("toml", "python"),
    "pyproject.toml": ("toml", "python"),
}


def _resolve_manifest_path(
    manifest_path: object,
) -> tuple[Optional[Path], str]:
    if manifest_path is None:
        return None, "PATH_IS_NONE"

    if not isinstance(manifest_path, (str, Path)):
        return None, "UNSUPPORTED_PATH_TYPE"

    raw = str(manifest_path).strip()

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


def select_manifest_parser(
    manifest_path: object,
) -> ManifestParserSelectionResult:
    path, status = _resolve_manifest_path(manifest_path)

    if path is None:
        return ManifestParserSelectionResult(
            manifest_path=None,
            parser=None,
            manifest_type=None,
            supported=False,
            status=status,
        )

    filename = path.name.lower()

    parser_info = MANIFEST_PARSER_MAP.get(filename)

    if parser_info is None:
        return ManifestParserSelectionResult(
            manifest_path=path,
            parser=None,
            manifest_type=None,
            supported=False,
            status="UNSUPPORTED_MANIFEST",
        )

    parser, manifest_type = parser_info

    return ManifestParserSelectionResult(
        manifest_path=path,
        parser=parser,
        manifest_type=manifest_type,
        supported=True,
        status="SELECTED",
    )
