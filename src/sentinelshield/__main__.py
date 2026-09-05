from __future__ import annotations

from sentinelshield.bootstrap import get_project_info
from sentinelshield.core_acceptance import MinimumCoreAcceptance
from sentinelshield.final_health_check import FinalHealthCheck


def main() -> int:
    print("=" * 50)
    print(" SENTINELSHIELD")
    print("=" * 50)

    info = get_project_info()

    print(f"PROJECT: {info['name']}")
    print(f"VERSION: {info['version']}")
    print()

    print("[1] CORE ACCEPTANCE")
    core = MinimumCoreAcceptance().require_accepted()
    print(
        f"CORE ACCEPTED: {core.accepted}"
    )
    print(
        f"CORE CHECKS: {len(core.checks)}"
    )

    print()
    print("[2] FINAL HEALTH CHECK")

    health = FinalHealthCheck().require_healthy()

    print(
        f"HEALTHY: {health.healthy}"
    )
    print(
        f"COMPONENTS: {len(health.components)}"
    )

    print()
    print("=" * 50)
    print(" SENTINELSHIELD READY")
    print("=" * 50)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
