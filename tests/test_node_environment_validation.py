from dataclasses import replace
from unittest.mock import patch

import pytest

from sentinelshield.node_environment_validation import (
    NodeEnvironmentValidationError,
    NodeEnvironmentValidationInput,
    NodeEnvironmentValidationResult,
    check_node_environment,
    is_node_environment_valid,
    node_environment_validation,
    validate_node_environment,
)


def test_node_environment_input_defaults():
    request = NodeEnvironmentValidationInput()

    assert request.min_node_major == 18
    assert request.max_node_major is None
    assert request.require_npm is True


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: {
        "node": "/usr/bin/node",
        "npm": "/usr/bin/npm",
    }.get(name),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_valid_node_environment(mock_run, mock_which):
    def command_result(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return type("Completed", (), {"stdout": "v20.11.1\n"})()

        return type("Completed", (), {"stdout": "10.2.4\n"})()

    mock_run.side_effect = command_result

    result = validate_node_environment()

    assert result.valid is True
    assert result.node_available is True
    assert result.node_major == 20
    assert result.node_version == "v20.11.1"
    assert result.npm_available is True
    assert result.npm_version == "10.2.4"
    assert result.reason == "NODE_ENVIRONMENT_VALID"


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    return_value=None,
)
def test_node_missing(mock_which):
    result = validate_node_environment()

    assert result.valid is False
    assert result.node_available is False
    assert result.reason == "NODE_NOT_FOUND"


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: (
        "/usr/bin/node" if name == "node" else "/usr/bin/npm"
    ),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_node_below_minimum(mock_run, mock_which):
    def command_result(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return type("Completed", (), {"stdout": "v16.20.2\n"})()

        return type("Completed", (), {"stdout": "8.19.4\n"})()

    mock_run.side_effect = command_result

    request = NodeEnvironmentValidationInput(
        min_node_major=18,
    )

    result = validate_node_environment(request)

    assert result.valid is False
    assert result.node_major == 16
    assert result.reason == "NODE_VERSION_BELOW_MINIMUM"


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: (
        "/usr/bin/node" if name == "node" else "/usr/bin/npm"
    ),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_node_above_maximum(mock_run, mock_which):
    def command_result(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return type("Completed", (), {"stdout": "v24.1.0\n"})()

        return type("Completed", (), {"stdout": "11.0.0\n"})()

    mock_run.side_effect = command_result

    request = NodeEnvironmentValidationInput(
        min_node_major=18,
        max_node_major=22,
    )

    result = validate_node_environment(request)

    assert result.valid is False
    assert result.node_major == 24
    assert result.reason == "NODE_VERSION_ABOVE_MAXIMUM"


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: (
        "/usr/bin/node" if name == "node" else None
    ),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_npm_required_but_missing(mock_run, mock_which):
    mock_run.return_value = type(
        "Completed",
        (),
        {"stdout": "v20.11.1\n"},
    )()

    request = NodeEnvironmentValidationInput(
        min_node_major=18,
        require_npm=True,
    )

    result = validate_node_environment(request)

    assert result.valid is False
    assert result.node_available is True
    assert result.npm_available is False
    assert result.reason == "NPM_NOT_FOUND"


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: (
        "/usr/bin/node" if name == "node" else None
    ),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_npm_optional(mock_run, mock_which):
    mock_run.return_value = type(
        "Completed",
        (),
        {"stdout": "v20.11.1\n"},
    )()

    request = NodeEnvironmentValidationInput(
        min_node_major=18,
        require_npm=False,
    )

    result = validate_node_environment(request)

    assert result.valid is True
    assert result.node_available is True
    assert result.npm_available is False
    assert result.reason == "NODE_ENVIRONMENT_VALID"


def test_invalid_input_type():
    with pytest.raises(TypeError, match="INPUT_MUST_BE"):
        validate_node_environment("invalid")


@pytest.mark.parametrize(
    "value",
    [
        -1,
        True,
        "18",
        1.5,
    ],
)
def test_invalid_minimum(value):
    with pytest.raises(
        (TypeError, NodeEnvironmentValidationError)
    ):
        validate_node_environment(
            NodeEnvironmentValidationInput(
                min_node_major=value
            )
        )


def test_invalid_maximum_order():
    with pytest.raises(
        NodeEnvironmentValidationError,
        match="MAX_NODE_MAJOR_MUST_NOT_BE_LESS",
    ):
        validate_node_environment(
            NodeEnvironmentValidationInput(
                min_node_major=20,
                max_node_major=18,
            )
        )


def test_invalid_require_npm():
    with pytest.raises(TypeError):
        validate_node_environment(
            NodeEnvironmentValidationInput(
                require_npm="yes"
            )
        )


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: {
        "node": "/usr/bin/node",
        "npm": "/usr/bin/npm",
    }.get(name),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_public_aliases(mock_run, mock_which):
    def command_result(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return type("Completed", (), {"stdout": "v20.11.1\n"})()

        return type("Completed", (), {"stdout": "10.2.4\n"})()

    mock_run.side_effect = command_result

    request = NodeEnvironmentValidationInput()

    first = validate_node_environment(request)
    second = node_environment_validation(request)
    third = check_node_environment(request)

    assert first == second == third
    assert is_node_environment_valid(request) is True


def test_result_is_dataclass():
    result = NodeEnvironmentValidationResult(
        valid=True,
        node_available=True,
        node_version="v20.0.0",
        node_major=20,
        npm_available=True,
        npm_version="10.0.0",
        platform="linux",
        node_executable="/usr/bin/node",
        npm_executable="/usr/bin/npm",
        reason="NODE_ENVIRONMENT_VALID",
    )

    assert result.valid is True
    assert result.node_major == 20


@patch(
    "sentinelshield.node_environment_validation.shutil.which",
    side_effect=lambda name: {
        "node": "/usr/bin/node",
        "npm": "/usr/bin/npm",
    }.get(name),
)
@patch(
    "sentinelshield.node_environment_validation.subprocess.run"
)
def test_node_command_is_called_with_version_flag(
    mock_run,
    mock_which,
):
    def command_result(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return type("Completed", (), {"stdout": "v20.0.0\n"})()

        return type("Completed", (), {"stdout": "10.0.0\n"})()

    mock_run.side_effect = command_result

    result = validate_node_environment()

    assert result.valid is True

    calls = mock_run.call_args_list

    assert calls[0].args[0] == [
        "/usr/bin/node",
        "--version",
    ]

    assert calls[1].args[0] == [
        "/usr/bin/npm",
        "--version",
    ]
