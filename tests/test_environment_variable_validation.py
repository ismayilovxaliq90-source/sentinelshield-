from types import MappingProxyType

import pytest

from sentinelshield.environment_variable_validation import (
    EnvironmentVariablePolicy,
    EnvironmentVariableValidationError,
    require_valid_environment,
    validate_environment,
    validate_environment_variables,
)


SAFE = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONUNBUFFERED",
    }
)


def policy(**kwargs):
    return EnvironmentVariablePolicy(
        allowed_names=SAFE,
        **kwargs,
    )


def test_valid_environment_passes():
    result = validate_environment_variables(
        {
            "PATH": "/usr/bin",
            "HOME": "/home/runner",
            "LANG": "C.UTF-8",
        },
        policy(),
    )

    assert result.valid is True
    assert result.failures == ()
    assert result.environment["PATH"] == "/usr/bin"


def test_environment_result_is_immutable():
    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        policy(),
    )

    assert isinstance(result.environment, MappingProxyType)

    with pytest.raises(TypeError):
        result.environment["PATH"] = "/tmp"


def test_input_mapping_is_not_modified():
    source = {"PATH": "/usr/bin"}

    validate_environment_variables(source, policy())

    assert source == {"PATH": "/usr/bin"}


def test_unknown_variable_is_rejected():
    result = validate_environment_variables(
        {"EVIL": "value"},
        policy(),
    )

    assert result.valid is False
    assert "VARIABLE_NOT_ALLOWED" in result.failures


def test_invalid_variable_name_is_rejected():
    result = validate_environment_variables(
        {"BAD-NAME": "value"},
        policy(),
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_NAME" in result.failures


def test_variable_name_must_not_start_with_digit():
    result = validate_environment_variables(
        {"1PATH": "value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({"1PATH"}),
        ),
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_NAME" in result.failures


def test_empty_variable_name_is_rejected():
    result = validate_environment_variables(
        {"": "value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({""}),
        ),
    )

    assert result.valid is False
    assert "EMPTY_VARIABLE_NAME" in result.failures


def test_non_string_name_is_rejected():
    result = validate_environment_variables(
        {123: "value"},
        policy(),
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_NAME_TYPE" in result.failures


def test_non_string_value_is_rejected():
    result = validate_environment_variables(
        {"PATH": 123},
        policy(),
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_VALUE_TYPE" in result.failures


def test_nul_in_name_is_rejected():
    result = validate_environment_variables(
        {"PATH\x00EVIL": "value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({"PATH\x00EVIL"}),
        ),
    )

    assert result.valid is False


def test_control_character_in_value_is_rejected():
    result = validate_environment_variables(
        {"PATH": "/usr/bin\nmalicious"},
        policy(),
    )

    assert result.valid is False
    assert "CONTROL_CHARACTER_IN_VALUE" in result.failures


def test_value_length_limit_is_enforced():
    result = validate_environment_variables(
        {"PATH": "x" * 20},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({"PATH"}),
            max_value_length=10,
        ),
    )

    assert result.valid is False
    assert "VARIABLE_VALUE_TOO_LONG" in result.failures


def test_name_length_limit_is_enforced():
    name = "A" * 20

    result = validate_environment_variables(
        {name: "value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({name}),
            max_name_length=10,
        ),
    )

    assert result.valid is False
    assert "VARIABLE_NAME_TOO_LONG" in result.failures


@pytest.mark.parametrize(
    "name",
    [
        "PASSWORD",
        "DB_PASSWORD",
        "API_TOKEN",
        "SECRET",
        "PRIVATE_KEY",
        "CREDENTIALS",
        "ACCESS_KEY",
    ],
)
def test_secret_like_variables_are_rejected(name):
    result = validate_environment_variables(
        {name: "secret-value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({name}),
            reject_secret_like_names=True,
        ),
    )

    assert result.valid is False
    assert "SECRET_LIKE_VARIABLE_REJECTED" in result.failures


def test_secret_like_variables_can_be_explicitly_allowed():
    result = validate_environment_variables(
        {"TOKEN": "safe-test-value"},
        EnvironmentVariablePolicy(
            allowed_names=frozenset({"TOKEN"}),
            reject_secret_like_names=False,
        ),
    )

    assert result.valid is True


def test_required_variable_must_exist():
    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        EnvironmentVariablePolicy(
            allowed_names=SAFE,
            required_names=frozenset({"HOME"}),
        ),
    )

    assert result.valid is False
    assert "REQUIRED_VARIABLE_MISSING" in result.failures


def test_required_variable_present_passes():
    result = validate_environment_variables(
        {"PATH": "/usr/bin", "HOME": "/home/runner"},
        EnvironmentVariablePolicy(
            allowed_names=SAFE,
            required_names=frozenset({"HOME"}),
        ),
    )

    assert result.valid is True


def test_required_name_outside_allowlist_rejected_by_policy():
    with pytest.raises(ValueError):
        EnvironmentVariablePolicy(
            allowed_names=frozenset({"PATH"}),
            required_names=frozenset({"HOME"}),
        )


def test_invalid_environment_type_fails():
    result = validate_environment_variables(
        ["PATH=/usr/bin"],
        policy(),
    )

    assert result.valid is False
    assert result.failures == ("INVALID_ENVIRONMENT_TYPE",)


def test_validate_environment_helper():
    result = validate_environment(
        {"PATH": "/usr/bin"},
        SAFE,
    )

    assert result.valid is True


def test_require_valid_environment_returns_mapping():
    result = require_valid_environment(
        {"PATH": "/usr/bin"},
        policy(),
    )

    assert result["PATH"] == "/usr/bin"


def test_require_valid_environment_raises_on_failure():
    with pytest.raises(EnvironmentVariableValidationError):
        require_valid_environment(
            {"EVIL": "value"},
            policy(),
        )


def test_multiple_failures_are_deduplicated():
    result = validate_environment_variables(
        {
            "BAD-NAME": "x",
            "EVIL": "x",
            "TOKEN": "x",
        },
        EnvironmentVariablePolicy(
            allowed_names=frozenset(
                {
                    "BAD-NAME",
                    "EVIL",
                    "TOKEN",
                }
            ),
        ),
    )

    assert result.valid is False
    assert len(result.failures) == len(set(result.failures))


def test_empty_environment_passes_when_no_required_values():
    result = validate_environment_variables(
        {},
        policy(),
    )

    assert result.valid is True
    assert result.environment == {}
