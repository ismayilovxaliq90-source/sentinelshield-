from __future__ import annotations

import json
import sys

from sentinelshield.tool_version_validation import (
    ToolVersionRequirement,
    ToolVersionValidationInput,
    validate_tool_versions,
)


def main() -> int:
    # These are tools that the Task 176-179 execution chain
    # needs on the isolated CI/server environment.
    request = ToolVersionValidationInput(
        requirements=(
            ToolVersionRequirement(
                name="python",
                min_version="3.10.0",
                required=True,
            ),
            ToolVersionRequirement(
                name="node",
                min_version="18.0.0",
                required=True,
            ),
            ToolVersionRequirement(
                name="npm",
                min_version="9.0.0",
                required=True,
            ),
            ToolVersionRequirement(
                name="git",
                min_version="2.0.0",
                required=True,
            ),
        ),
        timeout_seconds=10.0,
    )

    result = validate_tool_versions(request)

    payload = {
        "task": 180,
        "task_name": "Tool Version Validation",
        "execution_environment": "GitHub Actions",
        "valid": result.valid,
        "requested_count": result.requested_count,
        "available_count": result.available_count,
        "valid_count": result.valid_count,
        "invalid_count": result.invalid_count,
        "missing_count": result.missing_count,
        "reason": result.reason,
        "tools": [
            {
                "name": item.name,
                "available": item.available,
                "executable": item.executable,
                "version": item.version,
                "normalized_version": (
                    list(item.normalized_version)
                    if item.normalized_version is not None
                    else None
                ),
                "valid": item.valid,
                "reason": item.reason,
            }
            for item in result.tools
        ],
    }

    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
    )

    if not result.valid:
        print(
            f"TASK 180 — FAIL: {result.reason}",
            file=sys.stderr,
        )
        return 1

    print(
        "TASK 180 — TOOL VERSION VALIDATION: PASS"
    )
    print(
        "TASK 180 — EXECUTION ENVIRONMENT: "
        "GITHUB ACTIONS SERVER"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
