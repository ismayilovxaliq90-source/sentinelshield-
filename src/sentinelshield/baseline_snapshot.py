from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class BaselineSnapshotError(RuntimeError):
    """Raised when a baseline snapshot cannot be created safely."""


@dataclass(frozen=True)
class BaselineFile:
    path: str
    kind: str
    fingerprint: str


@dataclass(frozen=True)
class BaselineSnapshot:
    repository_root: str
    head: str
    branch: str | None
    files: tuple[BaselineFile, ...]
    status: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_root": self.repository_root,
            "head": self.head,
            "branch": self.branch,
            "files": [asdict(item) for item in self.files],
            "status": list(self.status),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        )


def _run_git(
    root: Path,
    args: list[str],
    timeout: float,
) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaselineSnapshotError(
            f"Git command failed: git {' '.join(args)}"
        ) from exc

    return result.stdout


def _fingerprint(path: Path) -> tuple[str, str]:
    try:
        if path.is_symlink():
            target = os.readlink(path)
            digest = hashlib.sha256(
                target.encode("utf-8", errors="surrogateescape")
            ).hexdigest()
            return "symlink", digest

        if path.is_file():
            hasher = hashlib.sha256()

            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)

            return "file", hasher.hexdigest()

        if path.is_dir():
            entries: list[str] = []

            for entry in sorted(
                path.iterdir(),
                key=lambda item: item.name,
            ):
                entries.append(
                    f"{entry.name}:{entry.is_symlink()}:{entry.is_dir()}"
                )

            digest = hashlib.sha256(
                "\n".join(entries).encode(
                    "utf-8",
                    errors="surrogateescape",
                )
            ).hexdigest()

            return "directory", digest

        stat = path.stat()
        metadata = (
            f"{stat.st_mode}:{stat.st_size}:"
            f"{stat.st_mtime_ns}"
        )

        digest = hashlib.sha256(
            metadata.encode("utf-8")
        ).hexdigest()

        return "other", digest

    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to fingerprint path: {path}"
        ) from exc


def _discover_repository_root(
    start_path: Path,
    timeout: float,
) -> Path:
    try:
        result = _run_git(
            start_path,
            [
                "rev-parse",
                "--show-toplevel",
            ],
            timeout,
        )
    except BaselineSnapshotError:
        raise

    root_text = result.strip()

    if not root_text:
        raise BaselineSnapshotError(
            "Git returned an empty repository root"
        )

    root = Path(root_text)

    try:
        root = root.resolve()
    except OSError as exc:
        raise BaselineSnapshotError(
            f"Unable to resolve repository root: {root}"
        ) from exc

    if not root.is_dir():
        raise BaselineSnapshotError(
            f"Repository root is not a directory: {root}"
        )

    return root


def _tracked_paths(
    root: Path,
    timeout: float,
) -> list[Path]:
    output = _run_git(
        root,
        [
            "ls-files",
            "-z",
        ],
        timeout,
    )

    paths: list[Path] = []

    for item in output.split("\0"):
        if not item:
            continue

        relative = Path(item)

        if relative.is_absolute():
            raise BaselineSnapshotError(
                f"Git returned an absolute tracked path: {item}"
            )

        paths.append(root / relative)

    return paths


def _status_entries(
    root: Path,
    timeout: float,
) -> list[str]:
    output = _run_git(
        root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
        ],
        timeout,
    )

    return [
        line
        for line in output.splitlines()
        if line
    ]


def create_baseline_snapshot(
    start_path: str | os.PathLike[str],
    timeout: float = 10.0,
) -> BaselineSnapshot:
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    try:
        start = Path(start_path).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise BaselineSnapshotError(
            "Unable to resolve start path"
        ) from exc

    if not start.exists():
        raise BaselineSnapshotError(
            f"Start path does not exist: {start}"
        )

    if not start.is_dir():
        raise BaselineSnapshotError(
            f"Start path is not a directory: {start}"
        )

    root = _discover_repository_root(
        start,
        timeout,
    )

    head = _run_git(
        root,
        [
            "rev-parse",
            "HEAD",
        ],
        timeout,
    ).strip()

    if not head:
        raise BaselineSnapshotError(
            "Repository HEAD is empty"
        )

    branch_output = _run_git(
        root,
        [
            "symbolic-ref",
            "--quiet",
            "--short",
            "HEAD",
        ],
        timeout,
    ).strip()

    branch = branch_output or None

    tracked = _tracked_paths(
        root,
        timeout,
    )

    status = _status_entries(
        root,
        timeout,
    )

    baseline_files: list[BaselineFile] = []

    seen: set[str] = set()

    for path in tracked:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise BaselineSnapshotError(
                f"Tracked path escapes repository root: {path}"
            ) from exc

        if relative in seen:
            continue

        seen.add(relative)

        if not path.exists() and not path.is_symlink():
            raise BaselineSnapshotError(
                f"Tracked path is missing: {relative}"
            )

        kind, fingerprint = _fingerprint(path)

        baseline_files.append(
            BaselineFile(
                path=relative,
                kind=kind,
                fingerprint=fingerprint,
            )
        )

    # Include paths appearing in the Git status that are not tracked.
    # This captures untracked files as part of the baseline as well.
    for line in status:
        if len(line) < 4:
            continue

        relative_text = line[3:]

        if " -> " in relative_text:
            relative_text = relative_text.split(
                " -> ",
                1,
            )[0]

        relative = Path(relative_text)

        if relative.is_absolute():
            continue

        relative_key = relative.as_posix()

        if relative_key in seen:
            continue

        candidate = root / relative

        if not candidate.exists() and not candidate.is_symlink():
            continue

        kind, fingerprint = _fingerprint(candidate)

        seen.add(relative_key)

        baseline_files.append(
            BaselineFile(
                path=relative_key,
                kind=kind,
                fingerprint=fingerprint,
            )
        )

    baseline_files.sort(
        key=lambda item: item.path
    )

    return BaselineSnapshot(
        repository_root=str(root),
        head=head,
        branch=branch,
        files=tuple(baseline_files),
        status=tuple(status),
    )
