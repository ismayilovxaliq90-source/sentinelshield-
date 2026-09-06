from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinelshield.project_orchestrator import ProjectOrchestrator


@dataclass(frozen=True)
class WatchTarget:
    name: str
    path: Path
    accepted: bool
    reason: str


class ProjectWatch:
    """
    Registers a project as a SentinelShield watch target.

    This step is intentionally read-only with respect to the
    target project: it does not execute or modify project code.
    """

    def __init__(
        self,
        orchestrator: ProjectOrchestrator | None = None,
    ):
        self.orchestrator = (
            orchestrator
            if orchestrator is not None
            else ProjectOrchestrator()
        )

    def add(
        self,
        name: str,
        path: str | Path,
    ) -> WatchTarget:
        target = Path(path).expanduser().resolve()

        if not target.exists():
            return WatchTarget(
                name=name,
                path=target,
                accepted=False,
                reason="PROJECT_NOT_FOUND",
            )

        if not target.is_dir():
            return WatchTarget(
                name=name,
                path=target,
                accepted=False,
                reason="NOT_A_DIRECTORY",
            )

        try:
            self.orchestrator.register(
                name=name,
                path=str(target),
            )
        except Exception as exc:
            return WatchTarget(
                name=name,
                path=target,
                accepted=False,
                reason=f"REGISTRATION_FAILED:{exc}",
            )

        inspection = self.orchestrator.inspect(name)

        return WatchTarget(
            name=name,
            path=target,
            accepted=inspection.accepted,
            reason=inspection.reason,
        )
