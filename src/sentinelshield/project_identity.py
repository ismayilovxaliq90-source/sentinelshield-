from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProjectIdentityResult:
    valid: bool
    project_path: Path | None
    identity: str | None
    reason: str


class ProjectIdentityGenerator:
    """
    Generates a deterministic identity for a project path.

    Identity is based on the canonical path only.
    No project code is executed and no filesystem content is hashed.
    """

    def generate(
        self,
        value: Any,
    ) -> ProjectIdentityResult:

        if value is None:
            return ProjectIdentityResult(
                valid=False,
                project_path=None,
                identity=None,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return ProjectIdentityResult(
                valid=False,
                project_path=None,
                identity=None,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return ProjectIdentityResult(
                    valid=False,
                    project_path=None,
                    identity=None,
                    reason="PATH_IS_EMPTY",
                )

        raw_path = str(value)

        if "\x00" in raw_path:
            return ProjectIdentityResult(
                valid=False,
                project_path=None,
                identity=None,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            project_path = (
                Path(value)
                .expanduser()
                .resolve(strict=False)
            )

        except (OSError, RuntimeError, ValueError) as exc:
            return ProjectIdentityResult(
                valid=False,
                project_path=None,
                identity=None,
                reason=(
                    "PATH_RESOLUTION_FAILED:"
                    f"{type(exc).__name__}"
                ),
            )

        identity = sha256(
            str(project_path).encode("utf-8")
        ).hexdigest()

        return ProjectIdentityResult(
            valid=True,
            project_path=project_path,
            identity=identity,
            reason="PROJECT_IDENTITY_GENERATED",
        )


def generate_project_identity(
    value: Any,
) -> ProjectIdentityResult:
    return ProjectIdentityGenerator().generate(value)
