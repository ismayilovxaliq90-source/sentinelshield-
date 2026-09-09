from __future__ import annotations

from pathlib import Path
from typing import Any


def normalize_project_path_whitespace(
    value: Any,
) -> Any:
    """
    Normalize only leading/trailing whitespace.

    Does not resolve paths, access the filesystem,
    execute commands, or modify files.
    """

    if value is None:
        return None

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, Path):
        return Path(str(value).strip())

    return value
