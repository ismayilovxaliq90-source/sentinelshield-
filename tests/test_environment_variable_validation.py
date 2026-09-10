from __future__ import annotations

from types import MappingProxyType

import pytest

from sentinelshield.environment_variable_validation import (
    EnvironmentVariablePolicy,
    EnvironmentVariableValidationError,
    EnvironmentVariableValidationResult,
    require_valid_environment,
    validate_environment,
    validate_environment_variables,
)


def make_policy(
    *,
    allowed=("PATH", "HOME", "LANG"),
    required=(),
    reject_secret_names=True,
):
    return EnvironmentVariablePolicy(
        allowed_names=frozenset(allowed),
        required_names=frozenset(required),
        reject_secret_names=reject_secret_names,
    )


def test_valid_allowlisted_environment_passes():
    result = validate_environment_variables(
        {
            "PATH": "/usr/bin",
            "HOME": "/home/runner",
            "LANG": "C.UTF-8",
        },
        make_policy(),
    )

    assert result.valid is True
    assert result.failures == ()
    assert result.environment["PATH"] == "/usr/bin"
    assert isinstance(result.environment, MappingProxyType)


def test_unknown_variable_is_rejected():
    result = validate_environment_variables(
        {"PATH": "/usr/bin", "UNKNOWN": "value"},
        make_policy(),
    )

    assert result.valid is False
    assert "VARIABLE_NOT_ALLOWLISTED:UNKNOWN" in result.failures
    assert "UNKNOWN" in result.rejected_names


def test_secret_like_variable_is_rejected():
    policy = make_policy(
        allowed=("PATH", "API_TOKEN"),
    )

    result = validate_environment_variables(
        {
            "PATH": "/usr/bin",
            "API_TOKEN": "secret-value",
        },
        policy,
    )

    assert result.valid is False
    assert "SECRET_VARIABLE_REJECTED:API_TOKEN" in result.failures


def test_secret_check_can_be_disabled():
    policy = make_policy(
        allowed=("API_TOKEN",),
        reject_secret_names=False,
    )

    result = validate_environment_variables(
        {"API_TOKEN": "test-value"},
        policy,
    )

    assert result.valid is True
    assert result.environment["API_TOKEN"] == "test-value"


def test_invalid_variable_name_is_rejected():
    policy = make_policy(allowed=("PATH", "BAD-NAME"))

    result = validate_environment_variables(
        {"BAD-NAME": "value"},
        policy,
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_NAME:BAD-NAME" in result.failures


def test_variable_name_must_not_start_with_digit():
    policy = make_policy(allowed=("1INVALID",))

    result = validate_environment_variables(
        {"1INVALID": "value"},
        policy,
    )

    assert result.valid is False
    assert "INVALID_VARIABLE_NAME:1INVALID" in result.failures


def test_empty_variable_name_is_rejected():
    policy = make_policy(allowed=("",))

    result = validate_environment_variables(
        {"": "value"},
        policy,
    )

    assert result.valid is False
    assert "VARIABLE_NAME_EMPTY" in result.failures


def test_nul_character_in_name_is_rejected():
    policy = make_policy(allowed=("SAFE",))

    result = validate_environment_variables(
        {"SAFE\x00BAD": "value"},
        policy,
    )

    assert result.valid is False


def test_control_character_in_value_is_rejected():
    policy = make_policy(allowed=("SAFE",))

    result = validate_environment_variables(
        {"SAFE": "hello\x01world"},
        policy,
    )

    assert result.valid is False
    assert "CONTROL_CHARACTER_IN_VALUE:SAFE" in result.failures


def test_nul_character_in_value_is_rejected():
    policy = make_policy(allowed=("SAFE",))

    result = validate_environment_variables(
        {"SAFE": "hello\x00world"},
        policy,
    )

    assert result.valid is False
    assert "CONTROL_CHARACTER_IN_VALUE:SAFE" in result.failures


def test_non_string_value_is_rejected():
    policy = make_policy(allowed=("SAFE",))

    result = validate_environment_variables(
        {"SAFE": 123},  # type: ignore[arg-type]
        policy,
    )

    assert result.valid is False
    assert "VARIABLE_VALUE_NOT_STRING:SAFE" in result.failures


def test_non_string_name_is_rejected():
    policy = make_policy()

    result = validate_environment_variables(
        {123: "value"},  # type: ignore[dict-item]
        policy,
    )

    assert result.valid is False
    assert "VARIABLE_NAME_NOT_STRING" in result.failures


def test_value_length_limit_is_enforced():
    policy = EnvironmentVariablePolicy(
        allowed_names=frozenset({"SAFE"}),
        max_value_length=4,
    )

    result = validate_environment_variables(
        {"SAFE": "12345"},
        policy,
    )

    assert result.valid is False
    assert "VARIABLE_VALUE_TOO_LONG:SAFE" in result.failures


def test_name_length_limit_is_enforced():
    long_name = "A" * 10

    policy = EnvironmentVariablePolicy(
        allowed_names=frozenset({long_name}),
        max_name_length=5,
    )

    result = validate_environment_variables(
        {long_name: "value"},
        policy,
    )

    assert result.valid is False
    assert f"VARIABLE_NAME_TOO_LONG:{long_name}" in result.failures


def test_required_variable_must_exist():
    policy = make_policy(required=("HOME",))

    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        policy,
    )

    assert result.valid is False
    assert "REQUIRED_VARIABLE_MISSING:HOME" in result.failures


def test_required_variable_must_also_be_valid():
    policy = make_policy(
        allowed=("PATH", "HOME"),
        required=("HOME",),
    )

    result = validate_environment_variables(
        {
            "PATH": "/usr/bin",
            "HOME": "bad\x00value",
        },
        policy,
    )

    assert result.valid is False
    assert "REQUIRED_VARIABLE_INVALID:HOME" in result.failures


def test_required_name_outside_allowlist_is_policy_failure():
    policy = EnvironmentVariablePolicy(
        allowed_names=frozenset({"PATH"}),
        required_names=frozenset({"HOME"}),
    )

    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        policy,
    )

    assert result.valid is False
    assert "REQUIRED_NAME_NOT_ALLOWLISTED" in result.failures


def test_none_environment_fails():
    result = validate_environment_variables(
        None,
        make_policy(),
    )

    assert result.valid is False
    assert "ENVIRONMENT_IS_NONE" in result.failures


@pytest.mark.parametrize(
    "environment",
    [
        [],
        "PATH=/usr/bin",
        123,
        object(),
    ],
)
def test_invalid_environment_type_fails(environment):
    result = validate_environment_variables(
        environment,  # type: ignore[arg-type]
        make_policy(),
    )

    assert result.valid is False
    assert "INVALID_ENVIRONMENT_TYPE" in result.failures


def test_empty_environment_passes_when_no_variables_required():
    result = validate_environment_variables(
        {},
        make_policy(),
    )

    assert result.valid is True
    assert result.environment == {}
    assert result.failures == ()


def test_result_is_immutable():
    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        make_policy(),
    )

    with pytest.raises(TypeError):
        result.environment["PATH"] = "/tmp"  # type: ignore[index]


def test_validated_environment_is_copy_not_original():
    source = {"PATH": "/usr/bin"}

    result = validate_environment_variables(
        source,
        make_policy(),
    )

    source["PATH"] = "/changed"

    assert result.environment["PATH"] == "/usr/bin"


def test_require_valid_environment_returns_immutable_mapping():
    environment = require_valid_environment(
        {"PATH": "/usr/bin"},
        make_policy(),
    )

    assert isinstance(environment, MappingProxyType)
    assert environment["PATH"] == "/usr/bin"


def test_require_valid_environment_raises_on_failure():
    with pytest.raises(EnvironmentVariableValidationError):
        require_valid_environment(
            {"UNKNOWN": "value"},
            make_policy(),
        )


def test_convenience_validate_environment_api():
    result = validate_environment(
        {"PATH": "/usr/bin"},
        allowed_names={"PATH"},
    )

    assert result.valid is True
    assert result.environment["PATH"] == "/usr/bin"


def test_failure_collection_is_tuple():
    result = validate_environment_variables(
        {"UNKNOWN": "value"},
        make_policy(),
    )

    assert isinstance(result.failures, tuple)


def test_accepted_names_are_sorted():
    policy = make_policy(
        allowed=("LANG", "PATH", "HOME"),
    )

    result = validate_environment_variables(
        {
            "LANG": "C",
            "PATH": "/usr/bin",
            "HOME": "/home/runner",
        },
        policy,
    )

    assert result.accepted_names == ("HOME", "LANG", "PATH")


def test_rejected_name_is_not_returned_as_accepted():
    result = validate_environment_variables(
        {
            "PATH": "/usr/bin",
            "UNKNOWN": "value",
        },
        make_policy(),
    )

    assert "UNKNOWN" not in result.accepted_names
    assert "UNKNOWN" in result.rejected_names


def test_to_dict_returns_serializable_copy():
    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        make_policy(),
    )

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["valid"] is True
    assert data["environment"] == {"PATH": "/usr/bin"}
    assert isinstance(data["failures"], list)


def test_policy_defaults_are_restrictive():
    policy = EnvironmentVariablePolicy()

    assert policy.reject_secret_names is True
    assert policy.reject_control_characters is True
    assert policy.max_name_length == 256
    assert policy.max_value_length == 8192
    assert policy.allowed_names == frozenset()


def test_validation_does_not_modify_source():
    source = {
        "PATH": "/usr/bin",
        "UNKNOWN": "value",
    }
    original = dict(source)

    validate_environment_variables(
        source,
        make_policy(),
    )

    assert source == original


def test_failure_list_never_uses_mutable_dict():
    result = validate_environment_variables(
        {"UNKNOWN": "value"},
        make_policy(),
    )

    assert result.failures == (
        "VARIABLE_NOT_ALLOWLISTED:UNKNOWN",
    )


def test_validation_result_has_expected_type():
    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        make_policy(),
    )

    assert isinstance(result, EnvironmentVariableValidationResult)


def test_no_execution_side_effects():
    policy = make_policy()

    result = validate_environment_variables(
        {"PATH": "/usr/bin"},
        policy,
    )

    assert result.valid is True
    assert result.environment["PATH"] == "/usr/bin"
