from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.project_health import (
    ProjectHealth,
    ProjectHealthChecker,
)
from sentinelshield.project_registry import (
    ProjectRecord,
    ProjectRegistry,
)


@dataclass(frozen=True)
class OrchestrationResult:
    project: str
    accepted: bool
    health: ProjectHealth
    reason: str


class ProjectOrchestrator:
    """
    Safe orchestration boundary.

    A project must:
      1. exist in the registry,
      2. be enabled,
      3. pass the read-only health check.

    This layer does not execute arbitrary project commands.
    """

    def __init__(
        self,
        registry: ProjectRegistry | None = None,
        health_checker: ProjectHealthChecker | None = None,
    ):
        self.registry = registry or ProjectRegistry()
        self.health_checker = health_checker or ProjectHealthChecker()

    def register(
        self,
        *,
        name: str,
        path: str,
        enabled: bool = True,
    ) -> ProjectRecord:
        return self.registry.register(
            name=name,
            path=path,
            enabled=enabled,
        )

    def inspect(self, name: str) -> OrchestrationResult:
        if not isinstance(name, str):
            raise TypeError("name must be str")

        project = self.registry.get(name)

        if project is None:
            raise KeyError(name)

        health = self.health_checker.check(project)

        if not project.enabled:
            return OrchestrationResult(
                project=project.name,
                accepted=False,
                health=health,
                reason="PROJECT_DISABLED",
            )

        if not health.healthy:
            return OrchestrationResult(
                project=project.name,
                accepted=False,
                health=health,
                reason="HEALTH_CHECK_FAILED",
            )

        return OrchestrationResult(
            project=project.name,
            accepted=True,
            health=health,
            reason="READY",
        )

    def ready(self, name: str) -> bool:
        return self.inspect(name).accepted

    def list_ready(self) -> tuple[OrchestrationResult, ...]:
        results = []

        for project in self.registry.list_projects():
            results.append(self.inspect(project.name))

        return tuple(
            result
            for result in results
            if result.accepted
        )
