from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path


ROOT = Path.cwd()

REQUIRED_MODULES = [
    "sentinelshield.bootstrap",
    "sentinelshield.runtime",
    "sentinelshield.resource_enforcement",
    "sentinelshield.resource_sampler",
    "sentinelshield.continuous_monitor",
    "sentinelshield.live_monitor",
    "sentinelshield.policy",
    "sentinelshield.action_controller",
    "sentinelshield.safe_execution_gateway",
    "sentinelshield.project_registry",
    "sentinelshield.project_health",
    "sentinelshield.project_orchestrator",
    "sentinelshield.self_healing",
    "sentinelshield.recovery_orchestrator",
    "sentinelshield.recovery_safety_gate",
    "sentinelshield.recovery_executor",
    "sentinelshield.recovery_pipeline",
    "sentinelshield.live_recovery_loop",
    "sentinelshield.event_engine",
    "sentinelshield.event_audit_bridge",
    "sentinelshield.alert_dispatcher",
    "sentinelshield.alert_store",
    "sentinelshield.alert_deduplicator",
    "sentinelshield.persistent_alert_pipeline",
    "sentinelshield.production_alert_pipeline",
    "sentinelshield.health_check",
    "sentinelshield.service_health",
    "sentinelshield.overall_health",
    "sentinelshield.watchdog",
]


def check_modules():
    failed = []

    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            failed.append(
                {
                    "module": module,
                    "error": repr(exc),
                }
            )

    return {
        "passed": not failed,
        "failed": failed,
        "count": len(REQUIRED_MODULES),
    }


def check_service():
    active = subprocess.run(
        ["systemctl", "is-active", "sentinelshield.service"],
        capture_output=True,
        text=True,
        check=False,
    )

    enabled = subprocess.run(
        ["systemctl", "is-enabled", "sentinelshield.service"],
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "active": active.returncode == 0
        and active.stdout.strip() == "active",
        "enabled": enabled.returncode == 0
        and enabled.stdout.strip() == "enabled",
    }


def check_directories():
    required = [
        ROOT / "src" / "sentinelshield",
        ROOT / "tests",
        ROOT / "runtime_data",
    ]

    return {
        str(path): path.is_dir()
        for path in required
    }


def main():
    modules = check_modules()
    service = check_service()
    directories = check_directories()

    directory_ok = all(directories.values())
    service_ok = (
        service["active"]
        and service["enabled"]
    )

    final_accepted = (
        modules["passed"]
        and service_ok
        and directory_ok
    )

    report = {
        "sentinelshield": "FINAL_ACCEPTANCE",
        "accepted": final_accepted,
        "modules": modules,
        "service": service,
        "directories": directories,
    }

    output = ROOT / "runtime_data" / "final_acceptance.json"
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print("=== FINAL ACCEPTANCE ===")
    print("MODULES:", modules["count"])
    print(
        "MODULE CHECK:",
        "PASS" if modules["passed"] else "FAIL",
    )
    print(
        "SERVICE ACTIVE:",
        "PASS" if service["active"] else "FAIL",
    )
    print(
        "SERVICE ENABLED:",
        "PASS" if service["enabled"] else "FAIL",
    )
    print(
        "DIRECTORIES:",
        "PASS" if directory_ok else "FAIL",
    )
    print()
    print(
        "FINAL ACCEPTED:",
        final_accepted,
    )
    print("REPORT:", output)

    if not final_accepted:
        if modules["failed"]:
            print()
            print("MODULE FAILURES:")
            for item in modules["failed"]:
                print(
                    item["module"],
                    "->",
                    item["error"],
                )

        raise SystemExit(1)

    print()
    print("SENTINELSHIELD FINAL ACCEPTANCE: PASS")


if __name__ == "__main__":
    main()
