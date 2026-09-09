from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".pytest_cache",
    "build", "dist", "target",
    ".next", ".nuxt", ".turbo",
}

NODE_MARKERS = {
    "package.json": "PACKAGE_JSON",
    "package-lock.json": "PACKAGE_LOCK_JSON",
    "npm-shrinkwrap.json": "NPM_SHRINKWRAP",
    "yarn.lock": "YARN_LOCK",
    "pnpm-lock.yaml": "PNPM_LOCK",
    "bun.lock": "BUN_LOCK",
    "bun.lockb": "BUN_LOCK",
    ".nvmrc": "NVMRC",
    ".node-version": "NODE_VERSION",
}

NODE_SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
}


@dataclass(frozen=True)
class NodeJSEcosystemResult:
    detected: bool
    root: Path | None
    markers: tuple[Path, ...]
    marker_types: tuple[str, ...]
    confidence: str
    reason: str


def detect_nodejs_ecosystem(value: Any) -> NodeJSEcosystemResult:
    if value is None:
        return NodeJSEcosystemResult(
            False, None, (), (), "NONE", "PATH_IS_NONE"
        )

    if not isinstance(value, (str, Path)):
        return NodeJSEcosystemResult(
            False, None, (), (), "NONE", "UNSUPPORTED_PATH_TYPE"
        )

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return NodeJSEcosystemResult(
                False, None, (), (), "NONE", "PATH_IS_EMPTY"
            )

    raw = str(value)

    if "\x00" in raw:
        return NodeJSEcosystemResult(
            False, None, (), (), "NONE",
            "NULL_CHARACTER_NOT_ALLOWED"
        )

    try:
        root = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return NodeJSEcosystemResult(
            False, None, (), (), "NONE",
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}"
        )

    if not root.exists():
        return NodeJSEcosystemResult(
            False, root, (), (), "NONE", "PATH_DOES_NOT_EXIST"
        )

    if not root.is_dir():
        return NodeJSEcosystemResult(
            False, root, (), (), "NONE", "PATH_IS_NOT_DIRECTORY"
        )

    found: dict[Path, str] = {}
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
                    if entry.name.lower() in IGNORED_DIRECTORIES:
                        continue
                    stack.append(entry)
                    continue

                if not entry.is_file():
                    continue

                name = entry.name.lower()
                marker_type = NODE_MARKERS.get(name)

                if marker_type is not None:
                    found[entry.relative_to(root)] = marker_type
                elif entry.suffix.lower() in NODE_SOURCE_EXTENSIONS:
                    found[entry.relative_to(root)] = "NODE_SOURCE"

            except (OSError, ValueError):
                continue

    ordered = sorted(found.items(), key=lambda item: item[0].as_posix())

    markers = tuple(path for path, _ in ordered)
    marker_types = tuple(marker for _, marker in ordered)

    strong = {
        "PACKAGE_JSON",
        "PACKAGE_LOCK_JSON",
        "NPM_SHRINKWRAP",
        "YARN_LOCK",
        "PNPM_LOCK",
        "BUN_LOCK",
    }

    if any(marker in strong for marker in marker_types):
        return NodeJSEcosystemResult(
            True,
            root,
            markers,
            marker_types,
            "HIGH",
            "NODEJS_ECOSYSTEM_DETECTED",
        )

    if any(
        marker in {"NVMRC", "NODE_VERSION", "NODE_SOURCE"}
        for marker in marker_types
    ):
        return NodeJSEcosystemResult(
            True,
            root,
            markers,
            marker_types,
            "MEDIUM",
            "NODEJS_ECOSYSTEM_DETECTED",
        )

    return NodeJSEcosystemResult(
        False,
        root,
        markers,
        marker_types,
        "NONE",
        "NODEJS_ECOSYSTEM_NOT_DETECTED",
    )
