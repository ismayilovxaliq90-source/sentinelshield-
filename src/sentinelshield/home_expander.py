from __future__ import annotations

from pathlib import Path
from typing import Any


def expand_user_home(value: Any) -> Any:
    """
    Expand only the current user's '~' home prefix.

    No filesystem traversal, project execution, package installation,
    or file modification is performed.
    """

    if value is None:
        return None

    if isinstance(value, str):
        if value == "~" or value.startswith("~/"):
            return str(Path(value).expanduser())

        return value

    if isinstance(value, Path):
        text = str(value)

        if text == "~" or text.startswith("~/"):
            return Path(text).expanduser()

        return value

    return value
