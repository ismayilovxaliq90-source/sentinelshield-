import math

import pytest

from sentinelshield.dry_run_result_validation import (
    DryRunResultValidationError,
    DryRunValidationPolicy,
    require_valid_dry_run_result,
    validate_dry_run_result,
)
from sentinelshield.remediation_dry_run import (
    RemediationDryRunResult,
)


def make_valid_result(**overrides):
    values = {
        "valid": True,
        "executable": "package-manager",
        "arguments": ("update", "package-a"),
        "working_directory": "/tmp/workspace",
        "environment_keys": ("CI",),
        "timeout_seconds": 60.0,
        "executed": False,
        "filesystem_modified": False,
        "reason": "DRY_RUN_VALIDATED_WITHOUT_EXECUTION",
    }

    values.update(overrides)

    return RemediationDryRunResult(**values)


def test_valid_dry_run_result_passes():
    result = validate_dry_run_result(
        make_valid_result()
    )

    assert result.valid is True
    assert result.executable == "package-manager"
    assert result.argument_count == 2
    assert result.executed is False
    assert result.filesystem_modified is False
    assert result.reason == "DRY_RUN_RESULT_VALID"


def test_invalid_result_type_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(object())


def test_invalid_flag_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(valid=False)
        )


def test_executed_result_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(executed=True)
        )


def test_filesystem_modified_result_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(filesystem_modified=True)
        )


def test_empty_executable_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(executable="")
        )


def test_whitespace_in_executable_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                executable="package manager"
            )
        )


def test_non_string_executable_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(executable=123)
        )


def test_arguments_must_be_tuple():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                arguments=["update"],
            )
        )


def test_argument_count_limit_is_enforced():
    policy = DryRunValidationPolicy(
        max_arguments=2,
    )

    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                arguments=("one", "two", "three"),
            ),
            policy,
        )


def test_non_string_argument_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                arguments=("update", 123),
            )
        )


def test_empty_argument_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                arguments=("update", ""),
            )
        )


def test_empty_working_directory_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                working_directory="",
            )
        )


def test_non_string_working_directory_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                working_directory=123,
            )
        )


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("inf"), float("-inf"), float("nan")],
)
def test_invalid_timeout_is_rejected(timeout):
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                timeout_seconds=timeout,
            )
        )


def test_timeout_below_minimum_is_rejected():
    policy = DryRunValidationPolicy(
        minimum_timeout_seconds=10.0,
        maximum_timeout_seconds=100.0,
    )

    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                timeout_seconds=9.9,
            ),
            policy,
        )


def test_timeout_above_maximum_is_rejected():
    policy = DryRunValidationPolicy(
        minimum_timeout_seconds=1.0,
        maximum_timeout_seconds=100.0,
    )

    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                timeout_seconds=100.1,
            ),
            policy,
        )


def test_timeout_boundaries_are_allowed():
    policy = DryRunValidationPolicy(
        minimum_timeout_seconds=1.0,
        maximum_timeout_seconds=100.0,
    )

    lower = validate_dry_run_result(
        make_valid_result(timeout_seconds=1.0),
        policy,
    )

    upper = validate_dry_run_result(
        make_valid_result(timeout_seconds=100.0),
        policy,
    )

    assert lower.timeout_seconds == 1.0
    assert upper.timeout_seconds == 100.0


def test_environment_keys_must_be_tuple():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                environment_keys=["CI"],
            )
        )


def test_empty_environment_key_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(
                environment_keys=("",),
            )
        )


def test_invalid_policy_type_is_rejected():
    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(),
            object(),
        )


def test_invalid_policy_max_arguments_is_rejected():
    policy = DryRunValidationPolicy(
        max_arguments=0,
    )

    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(),
            policy,
        )


def test_invalid_policy_timeout_range_is_rejected():
    policy = DryRunValidationPolicy(
        minimum_timeout_seconds=100.0,
        maximum_timeout_seconds=10.0,
    )

    with pytest.raises(DryRunResultValidationError):
        validate_dry_run_result(
            make_valid_result(),
            policy,
        )


def test_result_to_dict_contains_safe_validation_state():
    result = validate_dry_run_result(
        make_valid_result()
    )

    data = result.to_dict()

    assert data["valid"] is True
    assert data["argument_count"] == 2
    assert data["executed"] is False
    assert data["filesystem_modified"] is False


def test_validation_does_not_execute_any_command():
    result = validate_dry_run_result(
        make_valid_result()
    )

    assert result.executed is False
    assert result.filesystem_modified is False
    assert math.isfinite(result.timeout_seconds)


def test_require_valid_returns_validation_result():
    result = require_valid_dry_run_result(
        make_valid_result()
    )

    assert result.valid is True
    assert result.reason == "DRY_RUN_RESULT_VALID"
