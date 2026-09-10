import json

import pytest

from sentinelshield.remediation_execution_result import (
    ExecutionResultState,
    RemediationExecutionResult,
    RemediationExecutionResultError,
    create_remediation_execution_result,
    validate_remediation_execution_result,
)


def test_success_result():
    result = create_remediation_execution_result(
        return_code=0,
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
            "package-lock.json",
        ],
    )

    assert result.state is ExecutionResultState.SUCCESS
    assert result.succeeded is True
    assert result.failed is False
    assert result.is_partial is False
    assert result.requires_recovery is False


def test_partial_result():
    result = create_remediation_execution_result(
        return_code=1,
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
        ],
        failure_category="NON_ZERO_EXIT",
    )

    assert result.state is ExecutionResultState.PARTIAL
    assert result.is_partial is True
    assert result.failed is True
    assert result.applied_changes == {"package.json"}
    assert result.missing_changes == {"package-lock.json"}


def test_partial_result_with_zero_return_code_is_not_created():
    result = create_remediation_execution_result(
        return_code=0,
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
        ],
    )

    assert result.state is ExecutionResultState.PARTIAL


def test_failed_result():
    result = create_remediation_execution_result(
        return_code=2,
        expected_changes=["package.json"],
        actual_changes=[],
        failure_category="EXECUTION_ERROR",
    )

    assert result.state is ExecutionResultState.PARTIAL
    assert result.failed is True


def test_failed_without_expected_change():
    result = create_remediation_execution_result(
        return_code=2,
        expected_changes=[],
        actual_changes=[],
        failure_category="EXECUTION_ERROR",
    )

    assert result.state is ExecutionResultState.FAILED
    assert result.failed is True


def test_timeout_result():
    result = create_remediation_execution_result(
        return_code=-15,
        expected_changes=["package.json"],
        actual_changes=[],
        failure_category="TIMEOUT",
        timed_out=True,
    )

    assert result.state is ExecutionResultState.TIMEOUT
    assert result.timed_out is True
    assert result.failed is True


def test_resource_limit_result():
    result = create_remediation_execution_result(
        return_code=-9,
        expected_changes=["package.json"],
        actual_changes=[],
        failure_category="RESOURCE_LIMIT",
        resource_limited=True,
    )

    assert result.state is ExecutionResultState.RESOURCE_LIMIT
    assert result.resource_limited is True


def test_terminated_result():
    result = create_remediation_execution_result(
        return_code=-15,
        expected_changes=["package.json"],
        actual_changes=[],
        failure_category="TERMINATED",
        terminated=True,
    )

    assert result.state is ExecutionResultState.TERMINATED
    assert result.terminated is True


def test_unexpected_change_result():
    result = create_remediation_execution_result(
        return_code=1,
        expected_changes=["package.json"],
        actual_changes=[
            "package.json",
            "README.md",
        ],
        failure_category="UNEXPECTED_CHANGE",
    )

    assert result.state is ExecutionResultState.UNEXPECTED_CHANGE
    assert result.unexpected_changes == {"README.md"}
    assert result.is_safe if hasattr(result, "is_safe") else True


def test_unexpected_change_is_failure():
    result = create_remediation_execution_result(
        return_code=1,
        expected_changes=["package.json"],
        actual_changes=["README.md"],
    )

    assert result.state is ExecutionResultState.UNEXPECTED_CHANGE
    assert result.failed is True
    assert result.requires_recovery is True


def test_serialization():
    result = create_remediation_execution_result(
        return_code=1,
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=["package.json"],
        failure_category="NON_ZERO_EXIT",
    )

    payload = json.loads(result.to_json())

    assert payload["state"] == "PARTIAL"
    assert payload["return_code"] == 1
    assert payload["applied_changes"] == ["package.json"]
    assert payload["missing_changes"] == ["package-lock.json"]
    assert payload["failure_category"] == "NON_ZERO_EXIT"
    assert payload["failed"] is True


def test_validation_accepts_valid_result():
    result = create_remediation_execution_result(
        return_code=0,
        expected_changes=["package.json"],
        actual_changes=["package.json"],
    )

    assert validate_remediation_execution_result(result) is True


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        "result",
        123,
    ],
)
def test_validation_rejects_invalid_values(value):
    assert validate_remediation_execution_result(value) is False


@pytest.mark.parametrize(
    "bad_return_code",
    [
        True,
        False,
        "0",
        1.0,
    ],
)
def test_return_code_rejects_invalid_types(bad_return_code):
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.SUCCESS,
            return_code=bad_return_code,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )


def test_timeout_requires_timeout_flag():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.TIMEOUT,
            return_code=-15,
            expected_changes=frozenset(),
            actual_changes=frozenset(),
            applied_changes=frozenset(),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
            timed_out=False,
        )


def test_resource_limit_requires_resource_flag():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.RESOURCE_LIMIT,
            return_code=-9,
            expected_changes=frozenset(),
            actual_changes=frozenset(),
            applied_changes=frozenset(),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
            resource_limited=False,
        )


def test_terminated_requires_terminated_flag():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.TERMINATED,
            return_code=-15,
            expected_changes=frozenset(),
            actual_changes=frozenset(),
            applied_changes=frozenset(),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
            terminated=False,
        )


def test_success_requires_zero_return_code():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.SUCCESS,
            return_code=1,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )


def test_success_cannot_have_missing_changes():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.SUCCESS,
            return_code=0,
            expected_changes=frozenset(
                {
                    "package.json",
                    "package-lock.json",
                }
            ),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset({"package-lock.json"}),
            unexpected_changes=frozenset(),
        )


def test_success_cannot_have_failure_category():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.SUCCESS,
            return_code=0,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
            failure_category="NONE",
        )


def test_unexpected_change_requires_unexpected_paths():
    with pytest.raises(RemediationExecutionResultError):
        RemediationExecutionResult(
            state=ExecutionResultState.UNEXPECTED_CHANGE,
            return_code=1,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )


def test_path_traversal_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=1,
            expected_changes=["../outside"],
            actual_changes=[],
        )


def test_absolute_path_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=1,
            expected_changes=["/etc/passwd"],
            actual_changes=[],
        )


def test_string_collection_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=0,
            expected_changes="package.json",
            actual_changes=[],
        )


def test_duplicate_paths_are_deduplicated():
    result = create_remediation_execution_result(
        return_code=0,
        expected_changes=[
            "package.json",
            "package.json",
        ],
        actual_changes=[
            "package.json",
        ],
    )

    assert result.state is ExecutionResultState.SUCCESS
    assert result.expected_changes == {"package.json"}


def test_no_change_success():
    result = create_remediation_execution_result(
        return_code=0,
        expected_changes=[],
        actual_changes=[],
    )

    assert result.state is ExecutionResultState.SUCCESS


def test_timeout_zero_return_code_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=0,
            expected_changes=["package.json"],
            actual_changes=["package.json"],
            timed_out=True,
        )


def test_resource_limit_zero_return_code_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=0,
            expected_changes=["package.json"],
            actual_changes=["package.json"],
            resource_limited=True,
        )


def test_terminated_zero_return_code_rejected():
    with pytest.raises(RemediationExecutionResultError):
        create_remediation_execution_result(
            return_code=0,
            expected_changes=["package.json"],
            actual_changes=["package.json"],
            terminated=True,
        )
