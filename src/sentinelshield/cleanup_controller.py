from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil


class CleanupError(RuntimeError):
    """Raised when cleanup cannot be safely completed."""


@dataclass(frozen=True)
class CleanupAction:
    action: str
    path: str


@dataclass(frozen=True)
class CleanupResult:
    success: bool
    actions: tuple[CleanupAction, ...]
    errors: tuple[str, ...]


class CleanupController:
    """
    Task 34 — Cleanup Controller.

    Safely manages explicitly registered temporary paths.

    Only paths registered through this controller can be removed.
    Project/workspace files are never implicitly targeted.
    """

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()

        if not self.workspace.exists():
            raise CleanupError(
                f"workspace does not exist: {self.workspace}"
            )

        if not self.workspace.is_dir():
            raise CleanupError(
                f"workspace is not a directory: {self.workspace}"
            )

        self._registered: set[Path] = set()

    @property
    def registered_paths(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                path.relative_to(self.workspace).as_posix()
                for path in self._registered
            )
        )

    def register(self, path: str | Path) -> Path:
        candidate = Path(path)

        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.workspace / candidate).resolve()

        try:
            resolved.relative_to(self.workspace)
        except ValueError as exc:
            raise CleanupError(
                "cleanup path must remain inside workspace"
            ) from exc

        if resolved == self.workspace:
            raise CleanupError(
                "workspace root cannot be registered for cleanup"
            )

        self._registered.add(resolved)

        return resolved

    def unregister(self, path: str | Path) -> bool:
        candidate = Path(path)

        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.workspace / candidate).resolve()

        if resolved in self._registered:
            self._registered.remove(resolved)
            return True

        return False

    def clear_registry(self) -> None:
        self._registered.clear()

    def plan(self) -> tuple[CleanupAction, ...]:
        actions: list[CleanupAction] = []

        for path in sorted(self._registered):
            relative = path.relative_to(self.workspace).as_posix()

            if path.is_dir():
                actions.append(
                    CleanupAction(
                        action="REMOVE_DIRECTORY",
                        path=relative,
                    )
                )
            elif path.is_file() or path.is_symlink():
                actions.append(
                    CleanupAction(
                        action="REMOVE_FILE",
                        path=relative,
                    )
                )
            else:
                actions.append(
                    CleanupAction(
                        action="NOT_FOUND",
                        path=relative,
                    )
                )

        return tuple(actions)

    def execute(self) -> CleanupResult:
        actions = self.plan()
        errors: list[str] = []
        completed: list[CleanupAction] = []

        for action in actions:
            path = self.workspace / action.path

            try:
                if action.action == "REMOVE_DIRECTORY":
                    shutil.rmtree(path)

                elif action.action == "REMOVE_FILE":
                    path.unlink()

                elif action.action == "NOT_FOUND":
                    completed.append(action)
                    continue

                else:
                    raise CleanupError(
                        f"unsupported cleanup action: {action.action}"
                    )

                completed.append(action)

            except OSError as exc:
                errors.append(
                    f"{action.path}: {exc}"
                )

        for action in completed:
            self.unregister(action.path)

        return CleanupResult(
            success=len(errors) == 0,
            actions=tuple(completed),
            errors=tuple(errors),
        )
