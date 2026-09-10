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


def test_safe_command_and_environment_pass() -> None:
    result = validate_secret_exposure(
        ["git", "status"],
        {"PATH": "/usr/bin", "LANG": "C.UTF-8"},
    )

    assert result.safe is True
    assert result.failures == ()
    assert result.redacted_command == ("git", "status")
    assert dict(result.redacted_environment) == {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
    }


def test_secret_in_command_is_detected_and_redacted() -> None:
    result = validate_secret_exposure(
        ["tool", "--token", "super-secret-token"],
        {"PATH": "/usr/bin"},
        secret_values={"super-secret-token"},
    )

    assert result.safe is False
    assert any(
        failure.startswith("SECRET_EXPOSED_IN_COMMAND")
        for failure in result.failures
    )
    assert "super-secret-token" not in " ".join(result.redacted_command)
    assert "[REDACTED]" in result.redacted_command[-1]


def test_secret_in_environment_value_is_detected_and_redacted() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "prefix-secret-suffix"},
        secret_values={"secret"},
    )

    assert result.safe is False
    assert any(
        failure.startswith("SECRET_EXPOSED_IN_ENVIRONMENT")
        for failure in result.failures
    )
    assert "secret" not in result.redacted_environment["NORMAL"]
    assert "[REDACTED]" in result.redacted_environment["NORMAL"]


def test_secret_named_environment_is_rejected() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": "value"},
    )

    assert result.safe is False
    assert "SECRET_NAMED_ENVIRONMENT:API_TOKEN" in result.failures


def test_empty_secret_named_environment_does_not_expose_value() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": ""},
    )

    assert result.safe is True
    assert result.failures == ()


def test_secret_name_policy_can_be_disabled() -> None:
    policy = SecretExposurePolicy(
        reject_secret_named_environment=False,
    )

    result = validate_secret_exposure(
        ["tool"],
        {"API_TOKEN": "value"},
        policy=policy,
    )

    assert result.safe is True
    assert result.failures == ()


def test_redaction_handles_multiple_secrets() -> None:
    result = validate_secret_exposure(
        ["tool", "first-secret", "second-secret"],
        {"NORMAL": "first-secret:second-secret"},
        secret_values={"first-secret", "second-secret"},
    )

    assert result.safe is False
    assert all(
        secret not in " ".join(result.redacted_command)
        for secret in ("first-secret", "second-secret")
    )
    assert "first-secret" not in result.redacted_environment["NORMAL"]
    assert "second-secret" not in result.redacted_environment["NORMAL"]


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
    assert "COMMAND_ARGUMENT_TOO_LONG:1" in result.failures


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
    assert "ENVIRONMENT_NAME_TOO_LONG:ABCDE" in result.failures


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
    assert "ENVIRONMENT_VALUE_TOO_LONG:NORMAL" in result.failures


def test_null_character_is_rejected() -> None:
    result = validate_secret_exposure(
        ["tool", "safe\x00bad"],
        {},
    )

    assert result.safe is False
    assert "COMMAND_ARGUMENT:1:NULL_CHARACTER" in result.failures


def test_control_character_in_environment_is_rejected() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"NORMAL": "safe\nbad"},
    )

    assert result.safe is False
    assert "ENVIRONMENT_VALUE:NORMAL:CONTROL_CHARACTER" in result.failures


def test_non_string_command_argument_fails() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool", 123],
            {},
        )


def test_non_string_environment_name_fails() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {123: "value"},
        )


def test_non_string_environment_value_fails() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {"NORMAL": 123},
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


def test_environment_must_be_mapping() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            [("PATH", "/usr/bin")],
        )


def test_secret_values_must_be_strings() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {},
            secret_values={"secret", 123},
        )


def test_secret_values_string_is_rejected() -> None:
    with pytest.raises(TypeError):
        validate_secret_exposure(
            ["tool"],
            {},
            secret_values="secret",
        )


def test_result_failures_are_tuple() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {},
    )

    assert isinstance(result.failures, tuple)


def test_result_environment_is_immutable() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {"PATH": "/usr/bin"},
    )

    assert isinstance(result.redacted_environment, MappingProxyType)

    with pytest.raises(TypeError):
        result.redacted_environment["PATH"] = "changed"


def test_result_is_frozen() -> None:
    result = validate_secret_exposure(
        ["tool"],
        {},
    )

    with pytest.raises(AttributeError):
        result.safe = False


def test_exposed_property_matches_safe_state() -> None:
    safe_result = validate_secret_exposure(
        ["tool"],
        {},
    )

    exposed_result = validate_secret_exposure(
        ["tool", "secret-value"],
        {},
        secret_values={"secret-value"},
    )

    assert safe_result.exposed is False
    assert exposed_result.exposed is True


def test_vector_wrapper_matches_primary_function() -> None:
    first = validate_secret_exposure(
        ["tool", "secret-value"],
        {},
        secret_values={"secret-value"},
    )

    second = validate_secret_exposure_vector(
        ["tool", "secret-value"],
        {},
        secret_values={"secret-value"},
    )

    assert second == first


def test_require_passes_for_safe_input() -> None:
    result = require_no_secret_exposure(
        ["git", "status"],
        {"PATH": "/usr/bin"},
    )

    assert isinstance(result, SecretExposureResult)
    assert result.safe is True


def test_require_raises_for_exposure() -> None:
    with pytest.raises(SecretExposureError):
        require_no_secret_exposure(
            ["tool", "secret-value"],
            {},
            secret_values={"secret-value"},
        )


def test_secret_redaction_never_leaks_plaintext() -> None:
    secret = "VERY-SENSITIVE-VALUE"

    result = validate_secret_exposure(
        ["tool", "--value", secret],
        {"NORMAL": f"before-{secret}-after"},
        secret_values={secret},
    )

    rendered = repr(result)

    assert secret not in rendered
    assert secret not in " ".join(result.redacted_command)
    assert secret not in str(dict(result.redacted_environment))


def test_duplicate_failures_are_removed() -> None:
    result = validate_secret_exposure(
        ["tool", "secret", "secret"],
        {},
        secret_values={"secret"},
    )

    assert len(result.failures) == len(set(result.failures))
