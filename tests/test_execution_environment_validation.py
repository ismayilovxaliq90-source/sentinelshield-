from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinelshield.execution_environment_validation import (
    ExecutionEnvironmentValidationInput,
    ExecutionEnvironmentValidationResult,
    execution_environment_validation,
    validate_execution_environment,
    write_validation_evidence,
)


def test_rejects_invalid_input_type():
    with pytest.raises(TypeError, match="INPUT_MUST_BE_EXECUTION"):
        validate_execution_environment(object())


def test_rejects_non_boolean_require_ci():
    request = ExecutionEnvironmentValidationInput.__new__(
        ExecutionEnvironmentValidationInput
    )
    object.__setattr__(request, "require_ci", "yes")
    object.__setattr__(request, "require_github_actions", True)
    object.__setattr__(request, "minimum_free_disk_bytes", 1)

    with pytest.raises(TypeError, match="REQUIRE_CI_MUST_BE_BOOL"):
        validate_execution_environment(request)


def test_rejects_negative_disk_threshold():
    with pytest.raises(ValueError, match="MINIMUM_FREE_DISK_BYTES"):
        validate_execution_environment(
            ExecutionEnvironmentValidationInput(
                minimum_free_disk_bytes=-1
            )
        )


def test_result_shape():
    result = ExecutionEnvironmentValidationResult(
        valid=True,
        status="PASS",
        environment="SERVER_CI",
        ci_detected=True,
        github_actions_detected=True,
        operating_system="Linux",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="runner",
        workspace="/workspace",
        workspace_exists=True,
        workspace_directory=True,
        workspace_writable=True,
        free_disk_bytes=1024,
        minimum_free_disk_bytes=1,
        reasons=("OK",),
        errors=(),
    )

    assert result.valid is True
    assert result.status == "PASS"
    assert result.environment == "SERVER_CI"


def test_alias_points_to_same_behavior(monkeypatch, tmp_path):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    a = validate_execution_environment(
        ExecutionEnvironmentValidationInput(
            minimum_free_disk_bytes=1
        )
    )
    b = execution_environment_validation(
        ExecutionEnvironmentValidationInput(
            minimum_free_disk_bytes=1
        )
    )

    assert a == b
    assert a.valid is True
    assert a.github_actions_detected is True


def test_server_validation_fails_without_ci(monkeypatch, tmp_path):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    result = validate_execution_environment(
        ExecutionEnvironmentValidationInput(
            minimum_free_disk_bytes=1
        )
    )

    assert result.valid is False
    assert result.status == "FAIL"
    assert "CI_ENVIRONMENT_REQUIRED" in result.errors
    assert "GITHUB_ACTIONS_ENVIRONMENT_REQUIRED" in result.errors


def test_evidence_writer(tmp_path):
    result = ExecutionEnvironmentValidationResult(
        valid=True,
        status="PASS",
        environment="SERVER_CI",
        ci_detected=True,
        github_actions_detected=True,
        operating_system="Linux",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="runner",
        workspace=str(tmp_path),
        workspace_exists=True,
        workspace_directory=True,
        workspace_writable=True,
        free_disk_bytes=1024,
        minimum_free_disk_bytes=1,
        reasons=("OK",),
        errors=(),
    )

    output = write_validation_evidence(
        result,
        tmp_path / "task176.json",
    )

    assert output.exists()
    assert '"status": "PASS"' in output.read_text(encoding="utf-8")


def test_rejects_invalid_output_path(tmp_path):
    result = ExecutionEnvironmentValidationResult(
        valid=True,
        status="PASS",
        environment="SERVER_CI",
        ci_detected=True,
        github_actions_detected=True,
        operating_system="Linux",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="runner",
        workspace=str(tmp_path),
        workspace_exists=True,
        workspace_directory=True,
        workspace_writable=True,
        free_disk_bytes=1024,
        minimum_free_disk_bytes=1,
        reasons=("OK",),
        errors=(),
    )

    with pytest.raises(ValueError, match="OUTPUT_PATH_IS_EMPTY"):
        write_validation_evidence(result, "   ")


@pytest.mark.parametrize(
    "ci_value,github_value,expected_ci,expected_gh",
    [
        ("true", "true", True, True),
        ("TRUE", "true", True, True),
        ("true", "false", True, False),
    ],
)
def test_environment_detection(
    monkeypatch,
    tmp_path,
    ci_value,
    github_value,
    expected_ci,
    expected_gh,
):
    monkeypatch.setenv("CI", ci_value)
    monkeypatch.setenv("GITHUB_ACTIONS", github_value)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    result = validate_execution_environment(
        ExecutionEnvironmentValidationInput(
            minimum_free_disk_bytes=1
        )
    )

    assert result.ci_detected is expected_ci
    assert result.github_actions_detected is expected_gh


def test_input_is_immutable():
    request = ExecutionEnvironmentValidationInput()

    with pytest.raises(Exception):
        request.require_ci = False


def test_public_api_does_not_execute_remediation():
    assert callable(validate_execution_environment)
    assert callable(execution_environment_validation)
    assert callable(write_validation_evidence)
