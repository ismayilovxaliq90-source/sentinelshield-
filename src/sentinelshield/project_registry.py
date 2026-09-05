from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectRecord:
    name: str
    path: str
    enabled: bool = True


class ProjectRegistry:
    def __init__(self):
        self._projects: dict[str, ProjectRecord] = {}

    def register(
        self,
        *,
        name: str,
        path: str | Path,
        enabled: bool = True,
    ) -> ProjectRecord:
        if not isinstance(name, str):
            raise TypeError("name must be str")

        name = name.strip()

        if not name:
            raise ValueError("name must not be empty")

        if not isinstance(path, (str, Path)):
            raise TypeError("path must be str or Path")

        project_path = Path(path).expanduser()

        if not project_path.is_absolute():
            raise ValueError("project path must be absolute")

        project_path = project_path.resolve()

        if not project_path.exists():
            raise FileNotFoundError(str(project_path))

        if not project_path.is_dir():
            raise NotADirectoryError(str(project_path))

        if name in self._projects:
            raise ValueError(f"project already registered: {name}")

        if not isinstance(enabled, bool):
            raise TypeError("enabled must be bool")

        record = ProjectRecord(
            name=name,
            path=str(project_path),
            enabled=enabled,
        )

        self._projects[name] = record
        return record

    def unregister(self, name: str) -> None:
        if not isinstance(name, str):
            raise TypeError("name must be str")

        if name not in self._projects:
            raise KeyError(name)

        del self._projects[name]

    def get(self, name: str) -> ProjectRecord | None:
        return self._projects.get(name)

    def list_projects(self) -> tuple[ProjectRecord, ...]:
        return tuple(
            self._projects[name]
            for name in sorted(self._projects)
        )

    def exists(self, name: str) -> bool:
        return name in self._projects

    def count(self) -> int:
        return len(self._projects)
