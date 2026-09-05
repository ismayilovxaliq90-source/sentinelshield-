from __future__ import annotations

from dataclasses import dataclass

from sentinelshield.health_check import (
    HealthCheckResult,
    SentinelShieldHealthCheck,
)
from sentinelshield.service_health import (
    ServiceHealthResult,
    SystemdServiceHealth,
)


@dataclass(frozen=True)
class OverallHealthResult:
    healthy: bool
    application_healthy: bool
    service_healthy: bool
    application: HealthCheckResult
    service: ServiceHealthResult


class OverallHealthChecker:
    """
    Aggregates application health and systemd service health.

    Read-only: no start/stop/restart/enable/disable operations.
    """

    def __init__(
        self,
        application_checker: SentinelShieldHealthCheck,
        service_checker: SystemdServiceHealth,
    ):
        self.application_checker = application_checker
        self.service_checker = service_checker

    def check(self) -> OverallHealthResult:
        application = self.application_checker.run()
        service = self.service_checker.check()

        return OverallHealthResult(
            healthy=(
                application.healthy
                and service.healthy
            ),
            application_healthy=application.healthy,
            service_healthy=service.healthy,
            application=application,
            service=service,
        )
