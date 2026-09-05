from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class RollbackError(RuntimeError):
    """Raised when rollback cannot be safely completed."""


@dataclass(frozen=True)
class RollbackAction:
    action: str
    path: str


@dataclass(frozen=True)
class RollbackPlan:
    actions: tuple[RollbackAction, ...]

    @property
    def is_empty(self) -> bool:
        return len(self.actions) == 0


class RollbackController:
    """
    Task 32 — Rollback Controller.

    Compares a workspace against a trusted baseline and produces
    a deterministic rollback plan.

    The controller does not perform rollback automatically.
    """

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()

        if not self.workspace.exists():
            raise RollbackError(
                f"workspace does not exist: {self.workspace}"
            )

        if not self.workspace.is_dir():
            raise RollbackError(
                f"workspace is not a directory: {self.workspace}"
            )

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    def _current_files(self) -> dict[str, tuple[int, str]]:
        result: dict[str, tuple[int, str]] = {}

        for path in sorted(self.workspace.rglob("*")):
            if not path.is_file():
                continue

            relative = path.relative_to(self.workspace).as_posix()

            result[relative] = (
                path.stat().st_size,
                self._hash_file(path),
            )

        return result

    @staticmethod
    def _baseline_files(
        baseline: Iterable[dict],
    ) -> dict[str, tuple[int, str]]:
        result: dict[str, tuple[int, str]] = {}

        for entry in baseline:
            path = entry["path"]
            size = entry["size"]
            sha256 = entry["sha256"]

            result[path] = (
                size,
                sha256,
            )

        return result

    def create_plan(
        self,
        baseline: Iterable[dict],
    ) -> RollbackPlan:
        baseline_files = self._baseline_files(baseline)
        current_files = self._current_files()

        actions: list[RollbackAction] = []

        for path in sorted(current_files):
            if path not in baseline_files:
                actions.append(
                    RollbackAction(
                        action="DELETE",
                        path=path,
                    )
                )

        for path in sorted(baseline_files):
            if path not in current_files:
                actions.append(
                    RollbackAction(
                        action="MISSING",
                        path=path,
                    )
                )

        for path in sorted(
            set(baseline_files) & set(current_files)
        ):
            if baseline_files[path] != current_files[path]:
                actions.append(
                    RollbackAction(
                        action="RESTORE",
                        path=path,
                    )
                )

        return RollbackPlan(
            actions=tuple(actions)
        )

    def validate_plan(
        self,
        plan: RollbackPlan,
    ) -> bool:
        if not isinstance(plan, RollbackPlan):
            raise TypeError(
                "plan must be a RollbackPlan"
            )

        for action in plan.actions:
            if action.action not in {
                "DELETE",
                "MISSING",
                "RESTORE",
            }:
                return False

            if not action.path:
                return False

            path = Path(action.path)

            if path.is_absolute():
                return False

            if ".." in path.parts:
                return False

        return True
