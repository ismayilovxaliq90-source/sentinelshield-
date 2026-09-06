from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileChange:
    path: Path
    change: str


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    command: str


@dataclass(frozen=True)
class MonitorSnapshot:
    project_exists: bool
    files: tuple[Path, ...]
    processes: tuple[ProcessInfo, ...]
    fingerprint: str


class RealTimeProjectMonitor:
    """
    Read-only project monitor.

    It observes filesystem state and processes but never modifies
    project files and never terminates processes.
    """

    def __init__(self, project_path: str | Path):
        self.project_path = (
            Path(project_path)
            .expanduser()
            .resolve()
        )
        self._previous_files: set[Path] | None = None
        self._previous_fingerprint: str | None = None

    def _files(self) -> set[Path]:
        if not self.project_path.is_dir():
            return set()

        return {
            path
            for path in self.project_path.rglob("*")
            if path.is_file()
        }

    def _fingerprint(
        self,
        files: set[Path],
    ) -> str:
        digest = hashlib.sha256()

        for path in sorted(files):
            try:
                stat = path.stat()
            except OSError:
                continue

            relative = path.relative_to(
                self.project_path
            )

            digest.update(
                str(relative).encode("utf-8")
            )
            digest.update(
                str(stat.st_size).encode("utf-8")
            )
            digest.update(
                str(stat.st_mtime_ns).encode("utf-8")
            )

        return digest.hexdigest()

    def _processes(self) -> tuple[ProcessInfo, ...]:
        processes: list[ProcessInfo] = []

        proc = Path("/proc")

        if not proc.exists():
            return ()

        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue

            command_file = entry / "cmdline"

            try:
                raw = command_file.read_bytes()
            except OSError:
                continue

            command = raw.replace(
                b"\x00",
                b" ",
            ).decode(
                "utf-8",
                errors="replace",
            ).strip()

            if not command:
                continue

            processes.append(
                ProcessInfo(
                    pid=int(entry.name),
                    command=command,
                )
            )

        return tuple(
            sorted(
                processes,
                key=lambda item: item.pid,
            )
        )

    def snapshot(self) -> MonitorSnapshot:
        exists = self.project_path.is_dir()
        files = self._files()
        fingerprint = self._fingerprint(files)

        return MonitorSnapshot(
            project_exists=exists,
            files=tuple(sorted(files)),
            processes=self._processes(),
            fingerprint=fingerprint,
        )

    def changes(
        self,
        snapshot: MonitorSnapshot | None = None,
    ) -> tuple[FileChange, ...]:
        if snapshot is None:
            snapshot = self.snapshot()

        current = set(snapshot.files)

        if self._previous_files is None:
            changes = tuple(
                FileChange(
                    path=path,
                    change="INITIAL",
                )
                for path in sorted(current)
            )
        else:
            added = current - self._previous_files
            removed = self._previous_files - current

            changes = tuple(
                [
                    *(
                        FileChange(
                            path=path,
                            change="ADDED",
                        )
                        for path in sorted(added)
                    ),
                    *(
                        FileChange(
                            path=path,
                            change="REMOVED",
                        )
                        for path in sorted(removed)
                    ),
                ]
            )

        self._previous_files = current
        self._previous_fingerprint = snapshot.fingerprint

        return changes

    def poll(self) -> tuple[FileChange, ...]:
        return self.changes(self.snapshot())
