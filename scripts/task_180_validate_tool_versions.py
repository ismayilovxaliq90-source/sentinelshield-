from __future__ import annotations

import json
import sys

from sentinelshield.tool_version_validation import (
    ToolVersionRequirement,
    ToolVersionValidationInput,
    validate_tool_versions,
)


def main() -> int:
    # These are the baseline tools required by the CI
    # execution environment for the current server pipeline.
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="python3",
                min_version="3.11.0",
            ),
            ToolVersionRequirement(
                name="node",
                min_version="18.0.0",
            ),
            ToolVersionRequirement(
                name="npm",
                min_version="9.0.0",
            ),
            ToolVersionRequirement(
                name="git",
                min_version="2.0.0",
            ),
        ),
        timeout_seconds=10.0,
    )

    result = validate_tool_versions(request)

    evidence = {
        "task": 180,
        "task_name": "Tool Version Validation",
        "execution_environment": "GitHub Actions",
        "valid": result.valid,
        "reason": result.reason,
        "total_count": result.total_count,
        "available_count": result.available_count,
        "compatible_count": result.compatible_count,
        "missing_count": result.missing_count,
        "incompatible_count": result.incompatible_count,
        "tools": [
            {
                "name": item.name,
                "required": item.required,
                "available": item.available,
                "executable": item.executable,
                "version": item.version,
                "version_tuple": item.version_tuple,
                "compatible": item.compatible,
                "reason": item.reason,
            }
            for item in result.tools
        ],
    }

    print(
        json.dumps(
            evidence,
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
