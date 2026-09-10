from __future__ import annotations

import json
import sys

from sentinelshield.node_environment_validation import (
    NodeEnvironmentValidationInput,
    validate_node_environment,
)


def main() -> int:
    request = NodeEnvironmentValidationInput(
        min_node_major=18,
        max_node_major=None,
        require_npm=True,
    )

    result = validate_node_environment(request)

    evidence = {
        "task": 178,
        "task_name": "Node Environment Validation",
        "valid": result.valid,
        "node_available": result.node_available,
        "node_version": result.node_version,
        "node_major": result.node_major,
        "npm_available": result.npm_available,
        "npm_version": result.npm_version,
        "platform": result.platform,
        "node_executable": result.node_executable,
        "npm_executable": result.npm_executable,
        "reason": result.reason,
    }

    print(json.dumps(evidence, indent=2, sort_keys=True))

    if not result.valid:
        print(
            f"TASK 178 — FAIL: {result.reason}",
            file=sys.stderr,
        )
        return 1

    print(
        "TASK 178 — NODE ENVIRONMENT VALIDATION: PASS"
    )
    print(
        "TASK 178 — EXECUTION ENVIRONMENT: GITHUB ACTIONS SERVER"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
