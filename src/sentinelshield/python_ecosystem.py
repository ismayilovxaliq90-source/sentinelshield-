from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv",
    "env", ".env", "node_modules", "__pycache__",
    ".pytest_cache", "build", "dist", "target",
}

PYTHON_MARKERS = {
    "pyproject.toml": "PYPROJECT_TOML",
    "requirements.txt": "REQUIREMENTS_TXT",
    "pipfile": "PIPFILE",
    "setup.py": "SETUP_PY",
    "setup.cfg": "SETUP_CFG",
    "tox.ini": "TOX_INI",
    "pytest.ini": "PYTEST_INI",
    "poetry.lock": "POETRY_LOCK",
    "uv.lock": "UV_LOCK",
}


@dataclass(frozen=True)
class PythonEcosystemResult:
    detected: bool
    root: Path | None
    markers: tuple[Path, ...]
    marker_types: tuple[str, ...]
    confidence: str
    reason: str


def detect_python_ecosystem(value: Any) -> PythonEcosystemResult:
    if value is None:
        return PythonEcosystemResult(
            False, None, (), (), "NONE", "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return PythonEcosystemResult(
            False, None, (), (), "NONE", "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return PythonEcosystemResult(
                False, None, (), (), "NONE", "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return PythonEcosystemResult(
            False, None, (), (), "NONE",
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return PythonEcosystemResult(
            False, None, (), (), "NONE",
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return PythonEcosystemResult(
            False, root, (), (), "NONE", "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return PythonEcosystemResult(
            False, root, (), (), "NONE", "PATH_IS_NOT_DIRECTORY"
        )

    markers: list[Path] = []
    marker_types: list[str] = []

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

                marker_type = PYTHON_MARKERS.get(entry.name.lower())

                if marker_type is not None:
                    relative = entry.relative_to(root)
                    markers.append(relative)
                    marker_types.append(marker_type)

                # Python source itself is only a weak marker.
                elif entry.suffix.lower() == ".py":
                    relative = entry.relative_to(root)
                    markers.append(relative)
                    marker_types.append("PYTHON_SOURCE")

            except (OSError, ValueError):
                continue

    combined = sorted(
        zip(markers, marker_types),
        key=lambda item: item[0].as_posix(),
    )

    markers = [item[0] for item in combined]
    marker_types = [item[1] for item in combined]

    strong_types = {
        "PYPROJECT_TOML",
        "REQUIREMENTS_TXT",
        "PIPFILE",
        "SETUP_PY",
        "SETUP_CFG",
        "TOX_INI",
        "POETRY_LOCK",
        "UV_LOCK",
    }

    strong_count = sum(
        marker_type in strong_types
        for marker_type in marker_types
    )

    if strong_count >= 1:
        confidence = "HIGH"
        detected = True
        reason = "PYTHON_ECOSYSTEM_DETECTED"
    elif "PYTEST_INI" in marker_types or "PYTHON_SOURCE" in marker_types:
        confidence = "MEDIUM"
        detected = True
        reason = "PYTHON_ECOSYSTEM_DETECTED"
    else:
        confidence = "NONE"
        detected = False
        reason = "PYTHON_ECOSYSTEM_NOT_DETECTED"

    return PythonEcosystemResult(
        detected,
        root,
        tuple(markers),
        tuple(marker_types),
        confidence,
        reason,
    )
