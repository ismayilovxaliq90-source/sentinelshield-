from __future__ import annotations

import json
import sys

from sentinelshield.package_manager_availability_validation import (
    PackageManagerAvailabilityValidationInput,
    validate_package_manager_availability,
)


def main() -> int:
    request = PackageManagerAvailabilityValidationInput(
        package_managers=("npm",),
        require_all=True,
        version_timeout_seconds=10.0,
    )

    result = validate_package_manager_availability(request)

    payload = {
        "task": 179,
        "task_name": "Package Manager Availability Validation",
        "execution_environment": "GitHub Actions",
        "valid": result.valid,
        "requested_count": result.requested_count,
        "available_count": result.available_count,
        "missing_count": result.missing_count,
        "failed_version_count": result.failed_version_count,
        "require_all": result.require_all,
        "reason": result.reason,
        "package_managers": [
            {
                "name": item.name,
                "available": item.available,
                "executable": item.executable,
                "version": item.version,
                "reason": item.reason,
            }
            for item in result.package_managers
        ],
    }

    print(json.dumps(payload, indent=2, sort_keys=True))

    if not result.valid:
        print(
            f"TASK 179 — FAIL: {result.reason}",
            file=sys.stderr,
        )
        return 1

    print(
        "TASK 179 — PACKAGE MANAGER AVAILABILITY VALIDATION: PASS"
    )
    print(
        "TASK 179 — EXECUTION ENVIRONMENT: GITHUB ACTIONS SERVER"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
