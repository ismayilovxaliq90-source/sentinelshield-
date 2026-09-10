from __future__ import annotations

from types import MappingProxyType

import pytest

from sentinelshield.secret_exposure_prevention import (
    SecretExposureError,
    SecretExposurePolicy,
    SecretExposureResult,
    require_no_secret_exposure,
    validate_secret_exposure,
    validate_secret_exposure_vector,
)


def test_safe_command_passes() -> None:
    result = validate_secret_exposure(
        ["git", "status"],
        {"PATH": "/usr/bin", "LANG": "C.UTF-8"},
    )

    assert result.safe is True
    assert result.failures == ()
    assert result.redacted_command == (
        "git",
        "status",
    )


def test_safe_environment_passes() -> None:
    result = validate_secret_exposure(
        ["git", "status"],
        {"PATH": "/usr/bin"},
    )

    assert result.safe is True
    assert result.redacted_environment["PATH"] == "/usr/bin"


def test_secret_value_in_command_fails() -> None:
    result = validate_secret_exposure(
        ["tool", "--value", "SUPER_SECRET_VALUE"],
        {"PATH": "/usr/bin"},
        secret_values={"SUPER_SECRET_VALUE"},
    )

    assert result.safe is False
    assert any(
        item.startswith("SECRET_EXPOSED_IN_COMMAND:")
        for item in result.failures
    )


def test_secret_value_is_redacted_from_command() -> None:
    result = validate_secret_exposure(
        ["tool", "--value", "SUPER_SECRET_VALUE"],
        {},
        secret_values={"SUPER_SECRET_VALUE"},
    )

    assert "SUPER_SECRET_VALUE" not in (
        " ".join(result.redacted_command)
    )

    assert "[REDACTED]" in (
        " ".join(result.redacted_command)
    )


def test_secret_value_in_environment_fails() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "prefix-SUPER_SECRET_VALUE-suffix"},
        secret_values={"SUPER_SECRET_VALUE"},
    )

    assert result.safe is False
    assert any(
        item.startswith("SECRET_EXPOSED_IN_ENVIRONMENT:")
        for item in result.failures
    )


def test_secret_value_is_redacted_from_environment() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "prefix-SUPER_SECRET_VALUE-suffix"},
        secret_values={"SUPER_SECRET_VALUE"},
    )

    value = result.redacted_environment["NORMAL"]

    assert "SUPER_SECRET_VALUE" not in value
    assert "[REDACTED]" in value


def test_secret_named_environment_fails() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": "real-value"},
    )

    assert result.safe is False
    assert (
        "SECRET_NAMED_ENVIRONMENT:API_TOKEN"
        in result.failures
    )


def test_secret_named_environment_is_always_redacted() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": "real-value"},
    )

    assert (
        result.redacted_environment["API_TOKEN"]
        == "[REDACTED]"
    )


def test_empty_secret_named_environment_is_safe() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": ""},
    )

    assert result.safe is True
    assert result.failures == ()
    assert (
        result.redacted_environment["API_TOKEN"]
        == "[REDACTED]"
    )


def test_secret_environment_policy_can_be_disabled() -> None:
    policy = SecretExposurePolicy(
        reject_secret_named_environment=False,
    )

    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": "real-value"},
        policy=policy,
    )

    assert result.safe is True
    assert (
        result.redacted_environment["API_TOKEN"]
        == "[REDACTED]"
    )


def test_secret_command_option_is_detected() -> None:
    result = validate_secret_exposure(
        ["tool", "--token", "value"],
        {},
    )

    assert result.safe is False
    assert "SECRET_ARGUMENT_NAME:1" in result.failures


def test_secret_command_equals_form_is_detected() -> None:
    result = validate_secret_exposure(
        ["tool", "--token=value"],
        {},
    )

    assert result.safe is False
    assert "SECRET_ARGUMENT_NAME:1" in result.failures


def test_secret_command_equals_form_is_redacted() -> None:
    result = validate_secret_exposure(
        ["tool", "--token=VERY_SECRET"],
        {},
    )

    assert result.redacted_command == (
        "tool",
        "--token=[REDACTED]",
    )


def test_long_command_argument_fails() -> None:
    policy = SecretExposurePolicy(
        max_command_argument_length=4,
    )

    result = validate_secret_exposure(
        ["tool", "12345"],
        {},
        policy=policy,
    )

    assert result.safe is False
    assert (
        "COMMAND_ARGUMENT_TOO_LONG:1"
        in result.failures
    )


def test_long_environment_name_fails() -> None:
    policy = SecretExposurePolicy(
        max_environment_name_length=4,
    )

    result = validate_secret_exposure(
        ["tool"],
        {"ABCDE": "value"},
        policy=policy,
    )

    assert result.safe is False
    assert (
        "ENVIRONMENT_NAME_TOO_LONG:ABCDE"
        in result.failures
    )


def test_long_environment_value_fails() -> None:
    policy = SecretExposurePolicy(
        max_environment_value_length=4,
    )

    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "12345"},
        policy=policy,
    )

    assert result.safe is False
    assert (
        "ENVIRONMENT_VALUE_TOO_LONG:NORMAL"
        in result.failures
    )


def test_null_character_is_rejected() -> None:
    result = validate_secret_exposure(
        ["tool", "safe\x00bad"],
        {},
    )

    assert result.safe is False
    assert (
        "COMMAND_ARGUMENT:1:NULL_CHARACTER"
        in result.failures
    )


def test_control_character_is_rejected() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "safe\nbad"},
    )

    assert result.safe is False
    assert (
        "ENVIRONMENT_VALUE:NORMAL:CONTROL_CHARACTER"
        in result.failures
    )


def test_command_string_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            "git status",
            {},
        )


def test_bytes_command_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            b"git status",
            {},
        )


def test_non_string_command_argument_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool", 123],
            {},
        )


def test_environment_must_be_mapping() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            [("PATH", "/usr/bin")],
        )


def test_non_string_environment_name_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {123: "value"},
        )


def test_non_string_environment_value_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {"NORMAL": 123},
        )


def test_secret_values_string_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {},
            secret_values="secret",
        )


def test_secret_values_must_contain_strings() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {},
            secret_values={"secret", 123},
        )


def test_failures_are_tuple() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {},
    )

    assert isinstance(result.failures, tuple)


def test_redacted_environment_is_immutable() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"PATH": "/usr/bin"},
    )

    assert isinstance(
        result.redacted_environment,
        MappingProxyType,
    )

    with pytest.raises(TypeError):
        result.redacted_environment["PATH"] = "changed"


def test_result_is_frozen() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {},
    )

    with pytest.raises(AttributeError):
        result.safe = False


def test_result_to_dict_is_serializable() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"PATH": "/usr/bin"},
    )

    data = result.to_dict()

    assert data["safe"] is True
    assert data["failures"] == []
    assert data["redacted_command"] == ["tool"]
    assert data["redacted_environment"]["PATH"] == "/usr/bin"


def test_exposed_property_matches_safe_state() -> None:
    safe_result = validate_secret_exposure(
        ["tool"],
        {},
    )

    unsafe_result = validate_secret_exposure(
        ["tool", "SECRET_VALUE"],
        {},
        secret_values={"SECRET_VALUE"},
    )

    assert safe_result.exposed is False
    assert unsafe_result.exposed is True


def test_vector_wrapper_matches_primary_function() -> None:
    first = validate_secret_exposure(
        ["tool", "SECRET_VALUE"],
        {},
        secret_values={"SECRET_VALUE"},
    )

    second = validate_secret_exposure_vector(
        ["tool", "SECRET_VALUE"],
        {},
        secret_values={"SECRET_VALUE"},
    )

    assert second == first


def test_require_safe_input_returns_result() -> None:
    result = require_no_secret_exposure(
        ["git", "status"],
        {"PATH": "/usr/bin"},
    )

    assert isinstance(result, SecretExposureResult)
    assert result.safe is True


def test_require_unsafe_input_raises() -> None:
    with pytest.raises(SecretExposureError):
        require_no_secret_exposure(
            ["tool", "SECRET_VALUE"],
            {},
            secret_values={"SECRET_VALUE"},
        )


def test_plain_secret_never_appears_in_result() -> None:
    secret = "VERY_SENSITIVE_VALUE"

    result = validate_secret_exposure(
        ["tool", secret],
        {"NORMAL": f"before-{secret}-after"},
        secret_values={secret},
    )

    assert secret not in repr(result)
    assert secret not in str(result.to_dict())


def test_duplicate_failures_are_removed() -> None:
    result = validate_secret_exposure(
        ["tool", "--token=value"],
        {},
    )

    assert len(result.failures) == len(
        set(result.failures)
    )


def test_policy_rejects_boolean_integer_limits() -> None:
    with pytest.raises(TypeError):
        SecretExposurePolicy(
            max_command_argument_length=True
        )

    with pytest.raises(TypeError):
        SecretExposurePolicy(
            max_environment_name_length=False
        )

    with pytest.raises(TypeError):
        SecretExposurePolicy(
            max_environment_value_length=True
        )


def test_policy_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError):
        SecretExposurePolicy(
            max_command_argument_length=0
        )

    with pytest.raises(ValueError):
        SecretExposurePolicy(
            max_environment_name_length=0
        )

    with pytest.raises(ValueError):
        SecretExposurePolicy(
            max_environment_value_length=0
        )


def test_policy_rejects_invalid_boolean_types() -> None:
    with pytest.raises(TypeError):
        SecretExposurePolicy(
            reject_secret_named_environment=1
        )

    with pytest.raises(TypeError):
        SecretExposurePolicy(
            redact_secret_named_environment=1
        )

    with pytest.raises(TypeError):
        SecretExposurePolicy(
            reject_control_characters=1
        )


def test_custom_redaction_marker_is_supported() -> None:
    policy = SecretExposurePolicy(
        redaction_marker="<HIDDEN>",
    )

    result = validate_secret_exposure(
        ["tool", "SECRET"],
        {},
        secret_values={"SECRET"},
        policy=policy,
    )

    assert "<HIDDEN>" in result.redacted_command
    assert "SECRET" not in " ".join(
        result.redacted_command
    )
