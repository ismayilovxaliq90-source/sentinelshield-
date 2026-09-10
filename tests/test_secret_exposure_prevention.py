from __future__ import annotations

from types import MappingProxyType

import pytest

from sentinelshield.secret_exposure_prevention import (
    SecretExposure,
    SecretExposurePolicy,
    SecretExposurePreventionError,
    SecretExposureResult,
    inspect_secret_exposure,
    redact_secrets,
    require_no_secret_exposure,
    validate_command_secret_exposure,
    validate_secret_exposure,
)


def policy(*, secret_names=()):
    return SecretExposurePolicy(
        secret_names=frozenset(secret_names),
    )


def test_clean_text_is_safe():
    result = inspect_secret_exposure(
        "hello world",
        policy=policy(),
    )

    assert result.safe is True
    assert result.valid is True
    assert result.exposures == ()


def test_explicit_secret_value_is_detected():
    result = inspect_secret_exposure(
        "authorization=super-secret-value",
        environment={
            "TOKEN": "super-secret-value",
        },
        policy=policy(),
    )

    assert result.safe is False
    assert any(
        exposure.reason == "SECRET_VALUE_EXPOSURE"
        for exposure in result.exposures
    )


def test_secret_value_is_redacted():
    result = inspect_secret_exposure(
        "token=super-secret-value",
        environment={
            "TOKEN": "super-secret-value",
        },
        policy=policy(),
    )

    assert "super-secret-value" not in str(result.redacted)
    assert "***REDACTED***" in str(result.redacted)


def test_secret_name_is_detected():
    result = inspect_secret_exposure(
        {
            "API_TOKEN": "hidden-value",
        },
        policy=policy(),
    )

    assert result.safe is False
    assert any(
        exposure.reason == "SECRET_NAME_EXPOSURE"
        for exposure in result.exposures
    )


def test_secret_name_value_is_redacted():
    result = inspect_secret_exposure(
        {
            "API_TOKEN": "hidden-value",
        },
        policy=policy(),
    )

    redacted = result.redacted["value"]

    assert redacted["API_TOKEN"] == "***REDACTED***"


def test_secret_name_matching_is_case_insensitive():
    result = inspect_secret_exposure(
        {
            "api_token": "hidden-value",
        },
        policy=policy(),
    )

    assert result.safe is False


def test_password_is_detected():
    result = inspect_secret_exposure(
        {
            "PASSWORD": "hidden-value",
        },
        policy=policy(),
    )

    assert result.safe is False


def test_private_key_is_detected():
    result = inspect_secret_exposure(
        {
            "PRIVATE_KEY": "key-material",
        },
        policy=policy(),
    )

    assert result.safe is False


def test_credential_is_detected():
    result = inspect_secret_exposure(
        {
            "CREDENTIALS": "credential-value",
        },
        policy=policy(),
    )

    assert result.safe is False


def test_short_secret_is_not_value_matched():
    result = inspect_secret_exposure(
        "abc",
        environment={
            "TOKEN": "abc",
        },
        policy=SecretExposurePolicy(
            minimum_secret_length=4,
        ),
    )

    assert not any(
        exposure.reason == "SECRET_VALUE_EXPOSURE"
        for exposure in result.exposures
    )


def test_custom_secret_name_is_detected():
    result = inspect_secret_exposure(
        {
            "INTERNAL_KEY": "sensitive-value",
        },
        policy=policy(
            secret_names={"INTERNAL_KEY"},
        ),
    )

    assert result.safe is False


def test_custom_secret_name_matching_is_case_insensitive():
    result = inspect_secret_exposure(
        {
            "internal_key": "sensitive-value",
        },
        policy=policy(
            secret_names={"INTERNAL_KEY"},
        ),
    )

    assert result.safe is False


def test_custom_mask_is_used():
    custom = SecretExposurePolicy(
        secret_names=frozenset({"MY_SECRET"}),
        mask="[MASKED]",
    )

    result = inspect_secret_exposure(
        {
            "MY_SECRET": "sensitive-value",
        },
        policy=custom,
    )

    assert result.redacted["value"]["MY_SECRET"] == "[MASKED]"


def test_environment_is_redacted():
    result = inspect_secret_exposure(
        "normal",
        environment={
            "PATH": "/usr/bin",
            "API_TOKEN": "sensitive-value",
        },
        policy=policy(),
    )

    environment = result.redacted["environment"]

    assert environment["PATH"] == "/usr/bin"
    assert environment["API_TOKEN"] == "***REDACTED***"


def test_nested_mapping_is_redacted():
    result = inspect_secret_exposure(
        {
            "outer": {
                "TOKEN": "sensitive-value",
            }
        },
        policy=policy(),
    )

    nested = result.redacted["value"]["outer"]

    assert nested["TOKEN"] == "***REDACTED***"


def test_nested_list_is_redacted():
    result = inspect_secret_exposure(
        [
            "normal",
            "sensitive-value",
        ],
        environment={
            "TOKEN": "sensitive-value",
        },
        policy=policy(),
    )

    values = result.redacted["value"]

    assert values[0] == "normal"
    assert values[1] == "***REDACTED***"


def test_tuple_input_remains_tuple():
    result = inspect_secret_exposure(
        ("normal", "sensitive-value"),
        environment={
            "TOKEN": "sensitive-value",
        },
        policy=policy(),
    )

    assert isinstance(result.redacted["value"], tuple)


def test_set_input_becomes_frozenset():
    result = inspect_secret_exposure(
        {"normal", "safe-value"},
        policy=policy(),
    )

    assert isinstance(result.redacted["value"], frozenset)


def test_none_value_is_safe():
    result = inspect_secret_exposure(
        None,
        policy=policy(),
    )

    assert result.safe is True
    assert result.exposures == ()


def test_none_environment_is_safe():
    result = inspect_secret_exposure(
        "hello",
        environment=None,
        policy=policy(),
    )

    assert result.safe is True


def test_empty_environment_is_safe():
    result = inspect_secret_exposure(
        "hello",
        environment={},
        policy=policy(),
    )

    assert result.safe is True


def test_original_environment_is_not_modified():
    environment = {
        "PATH": "/usr/bin",
        "API_TOKEN": "sensitive-value",
    }

    original = dict(environment)

    inspect_secret_exposure(
        "hello",
        environment=environment,
        policy=policy(),
    )

    assert environment == original


def test_original_mapping_is_not_modified():
    value = {
        "API_TOKEN": "sensitive-value",
        "safe": "value",
    }

    original = dict(value)

    inspect_secret_exposure(
        value,
        policy=policy(),
    )

    assert value == original


def test_result_is_immutable():
    result = inspect_secret_exposure(
        "hello",
        policy=policy(),
    )

    assert isinstance(result, SecretExposureResult)

    with pytest.raises(Exception):
        result.safe = False  # type: ignore[misc]


def test_redacted_mapping_is_immutable():
    result = inspect_secret_exposure(
        {
            "safe": "value",
        },
        policy=policy(),
    )

    assert isinstance(result.redacted, MappingProxyType)

    with pytest.raises(TypeError):
        result.redacted["x"] = "y"  # type: ignore[index]


def test_exposure_is_immutable():
    exposure = SecretExposure(
        location="value",
        reason="SECRET_VALUE_EXPOSURE",
    )

    with pytest.raises(Exception):
        exposure.location = "changed"  # type: ignore[misc]


def test_exception_does_not_contain_secret_value():
    secret = "super-secret-value"

    with pytest.raises(SecretExposurePreventionError) as exc_info:
        require_no_secret_exposure(
            f"token={secret}",
            environment={
                "TOKEN": secret,
            },
            policy=policy(),
        )

    assert secret not in str(exc_info.value)
    assert "SECRET_EXPOSURE_DETECTED" in str(exc_info.value)


def test_require_no_secret_exposure_returns_redacted_data():
    result = require_no_secret_exposure(
        {
            "TOKEN": "sensitive-value",
            "normal": "value",
        },
        policy=policy(),
    )

    assert result["value"]["TOKEN"] == "***REDACTED***"
    assert result["value"]["normal"] == "value"


def test_redact_secrets_returns_safe_representation():
    result = redact_secrets(
        {
            "PASSWORD": "sensitive-value",
        },
        policy=policy(),
    )

    assert result["value"]["PASSWORD"] == "***REDACTED***"


def test_validate_alias_matches_primary_api():
    first = inspect_secret_exposure(
        "hello",
        policy=policy(),
    )

    second = validate_secret_exposure(
        "hello",
        policy=policy(),
    )

    assert first.safe == second.safe
    assert first.exposures == second.exposures


def test_command_secret_exposure_is_data_only():
    result = validate_command_secret_exposure(
        (
            "python3",
            "-c",
            "print(sensitive-value)",
        ),
        environment={
            "TOKEN": "sensitive-value",
        },
        policy=policy(),
    )

    assert result.safe is False
    assert "sensitive-value" not in str(result.redacted)


def test_command_must_be_sequence():
    with pytest.raises(SecretExposurePreventionError):
        validate_command_secret_exposure(  # type: ignore[arg-type]
            "python3 -c something",
            policy=policy(),
        )


def test_invalid_policy_fails():
    with pytest.raises(SecretExposurePreventionError):
        inspect_secret_exposure(
            "hello",
            policy=None,  # replaced below by default
        )

    # Explicit invalid object must fail.
    with pytest.raises(SecretExposurePreventionError):
        inspect_secret_exposure(
            "hello",
            policy="invalid",  # type: ignore[arg-type]
        )


def test_invalid_mask_fails():
    with pytest.raises(SecretExposurePreventionError):
        inspect_secret_exposure(
            "hello",
            policy=SecretExposurePolicy(mask=""),
        )


def test_invalid_minimum_secret_length_fails():
    with pytest.raises(SecretExposurePreventionError):
        inspect_secret_exposure(
            "hello",
            policy=SecretExposurePolicy(
                minimum_secret_length=0,
            ),
        )


def test_custom_location_is_preserved():
    result = inspect_secret_exposure(
        "sensitive-value",
        environment={
            "TOKEN": "sensitive-value",
        },
        policy=policy(),
        location="stdout",
    )

    assert any(
        exposure.location == "stdout"
        for exposure in result.exposures
    )


def test_exposure_locations_do_not_contain_secret_values():
    secret = "super-secret-value"

    result = inspect_secret_exposure(
        secret,
        environment={
            "TOKEN": secret,
        },
        policy=policy(),
    )

    for exposure in result.exposures:
        assert secret not in exposure.location
        assert secret not in exposure.reason


def test_to_dict_never_contains_secret_value():
    secret = "super-secret-value"

    result = inspect_secret_exposure(
        {
            "TOKEN": secret,
        },
        policy=policy(),
    )

    data = result.to_dict()

    assert secret not in str(data)
