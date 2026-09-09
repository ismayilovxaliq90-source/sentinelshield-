from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


TEST_DIRECTORY_NAMES = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
    }
)

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        "target",
        "coverage",
    }
)


@dataclass(frozen=True)
class TestTreeDiscoveryResult:
    __test__ = False
    valid: bool
    project_root: Path | None
    test_roots: tuple[Path, ...]
    reason: str


class TestTreeDetector:
    """Discovers test directories without executing project code."""

    def discover(self, value: Any) -> TestTreeDiscoveryResult:
        if value is None:
            return TestTreeDiscoveryResult(
                False, None, (), "PATH_IS_NONE"
            )

        if not isinstance(value, (str, Path)):
            return TestTreeDiscoveryResult(
                False, None, (), "UNSUPPORTED_PATH_TYPE"
            )

        if isinstance(value, str):
            value = value.strip()
            if not value:
                return TestTreeDiscoveryResult(
                    False, None, (), "PATH_IS_EMPTY"
                )

        raw = str(value)

        if "\x00" in raw:
            return TestTreeDiscoveryResult(
                False,
                None,
                (),
                "NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            root = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return TestTreeDiscoveryResult(
                False,
                None,
                (),
                f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
            )

        if root.exists() and not root.is_dir():
            root = root.parent

        if not root.exists():
            return TestTreeDiscoveryResult(
                False, root, (), "DIRECTORY_NOT_FOUND"
            )

        if not root.is_dir():
            return TestTreeDiscoveryResult(
                False, root, (), "PATH_IS_NOT_DIRECTORY"
            )

        return TestTreeDiscoveryResult(
            True,
            root,
            self._discover(root),
            "TEST_TREE_DISCOVERY_SUCCESS",
        )

    def _discover(self, root: Path) -> tuple[Path, ...]:
        found: set[Path] = set()

        def scan(directory: Path) -> None:
            try:
                entries = sorted(
                    directory.iterdir(),
                    key=lambda p: p.name,
                )
            except OSError:
                return

            for entry in entries:
                if not entry.is_dir() or entry.is_symlink():
                    continue

                if entry.name in IGNORED_DIRECTORY_NAMES:
                    continue

                if entry.name in TEST_DIRECTORY_NAMES:
                    found.add(entry)
                    continue

                scan(entry)

        scan(root)

        return tuple(
            sorted(found, key=lambda p: str(p))
        )


def discover_test_tree(value: Any) -> TestTreeDiscoveryResult:
    return TestTreeDetector().discover(value)
