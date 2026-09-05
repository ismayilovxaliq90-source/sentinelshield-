from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class BaselineSnapshot:
    """
    Task 31 — Baseline Snapshot

    Creates a deterministic snapshot of the current SentinelShield
    execution environment and selected workspace metadata.
    """

    def __init__(self, workspace: str | os.PathLike[str]):
        self.workspace = Path(workspace).resolve()

    def _file_hash(self, path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def _workspace_files(self) -> list[dict[str, Any]]:
        if not self.workspace.exists():
            return []

        files: list[dict[str, Any]] = []

        for path in sorted(self.workspace.rglob("*")):
            if not path.is_file():
                continue

            try:
                relative = path.relative_to(self.workspace)
                stat = path.stat()

                files.append(
                    {
                        "path": relative.as_posix(),
                        "size": stat.st_size,
                        "sha256": self._file_hash(path),
                    }
                )
            except (OSError, ValueError):
                continue

        return files

    def capture(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "python": {
                "version": platform.python_version(),
                "executable": sys.executable,
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "workspace": str(self.workspace),
            "files": self._workspace_files(),
        }

    def save(self, output: str | os.PathLike[str]) -> Path:
        destination = Path(output)

        if not destination.is_absolute():
            destination = self.workspace / destination

        destination.parent.mkdir(parents=True, exist_ok=True)

        snapshot = self.capture()

        destination.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        return destination


__all__ = ["BaselineSnapshot"]
