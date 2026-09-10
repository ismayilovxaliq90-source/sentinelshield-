from __future__ import annotations

import json
import platform
import sys

import pytest

from sentinelshield.python_virtual_environment_validation import (
    PythonVirtualEnvironmentValidationInput,
    PythonVirtualEnvironmentValidationResult,
    python_virtual_environment_validation,
    validate_python_virtual_environment,
    write_validation_evidence,
)


def test_rejects_invalid_input():
    with pytest.raises(TypeError):
        validate_python_virtual_environment(object())


def test_rejects_invalid_boolean():
    request = PythonVirtualEnvironmentValidationInput.__new__(
        PythonVirtualEnvironmentValidationInput
    )
    object.__setattr__(request, "environment_path", None)
    object.__setattr__(
        request,
        "require_virtual_environment",
        "yes",
    )

    with pytest.raises(
        TypeError,
        match="REQUIRE_VIRTUAL_ENVIRONMENT_MUST_BE_BOOL",
    ):
        validate_python_virtual_environment(request)


def test_rejects_empty_environment_path():
    with pytest.raises(
        ValueError,
        match="ENVIRONMENT_PATH_IS_EMPTY",
    ):
        validate_python_virtual_environment(
            PythonVirtualEnvironmentValidationInput(
                environment_path="   "
            )
        )


def test_missing_environment_fails(tmp_path):
    result = validate_python_virtual_environment(
        PythonVirtualEnvironmentValidationInput(
            environment_path=tmp_path / "missing"
        )
    )

    assert result.valid is False
    assert result.status == "FAIL"
    assert "VIRTUAL_ENVIRONMENT_DIRECTORY_MISSING" in result.errors


def test_result_is_immutable():
    result = PythonVirtualEnvironmentValidationResult(
        valid=True,
        status="PASS",
        environment_path="/venv",
        environment_exists=True,
        pyvenv_cfg_exists=True,
        python_executable="/venv/bin/python",
        python_executable_exists=True,
        interpreter_prefix="/venv",
        base_prefix="/usr",
        interpreter_is_virtual_environment=True,
        python_version="3.12.0",
        platform="Linux",
        reasons=("OK",),
        errors=(),
    )

    with pytest.raises(Exception):
        result.status = "FAIL"


def test_alias():
    a = python_virtual_environment_validation(
        PythonVirtualEnvironmentValidationInput(
            environment_path="/definitely/missing"
        )
    )

    b = validate_python_virtual_environment(
        PythonVirtualEnvironmentValidationInput(
            environment_path="/definitely/missing"
        )
    )

    assert a == b


def test_evidence_writer(tmp_path):
    result = PythonVirtualEnvironmentValidationResult(
        valid=True,
        status="PASS",
        environment_path="/venv",
        environment_exists=True,
        pyvenv_cfg_exists=True,
        python_executable="/venv/bin/python",
        python_executable_exists=True,
        interpreter_prefix="/venv",
        base_prefix="/usr",
        interpreter_is_virtual_environment=True,
        python_version="3.12.0",
        platform="Linux",
        reasons=("OK",),
        errors=(),
    )

    output = write_validation_evidence(
        result,
        tmp_path / "task177.json",
    )

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["status"] == "PASS"
    assert data["valid"] is True
    assert isinstance(data["reasons"], list)
    assert isinstance(data["errors"], list)


def test_public_api_is_callable():
    assert callable(validate_python_virtual_environment)
    assert callable(python_virtual_environment_validation)
    assert callable(write_validation_evidence)
