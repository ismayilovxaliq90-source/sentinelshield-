import pytest

from sentinelshield.secret_guard import (
    SecretExposureError,
    SecretExposureGuard,
)


@pytest.fixture
def guard():
    return SecretExposureGuard()


def test_normal_text_is_safe(guard):
    result = guard.scan("application started successfully")

    assert result.safe is True
    assert result.matches == ()


def test_api_key_pattern_is_detected(guard):
    result = guard.scan(
        "api_key=super-secret-value-123"
    )

    assert result.safe is False


def test_password_pattern_is_detected(guard):
    result = guard.scan(
        "password=my-secret-password"
    )

    assert result.safe is False


def test_token_pattern_is_detected(guard):
    result = guard.scan(
        "access_token=very-secret-token"
    )

    assert result.safe is False


def test_bearer_token_is_detected(guard):
    result = guard.scan(
        "Authorization: Bearer ABCDEFGHIJKLMNOP"
    )

    assert result.safe is False


def test_aws_style_access_key_is_detected(guard):
    result = guard.scan(
        "AKIAIOSFODNN7EXAMPLE"
    )

    assert result.safe is False


def test_private_key_is_detected(guard):
    result = guard.scan(
        "-----BEGIN PRIVATE KEY-----"
    )

    assert result.safe is False


def test_validate_rejects_secret(guard):
    with pytest.raises(SecretExposureError):
        guard.validate(
            "password=super-secret"
        )


def test_validate_accepts_normal_text(guard):
    result = guard.validate(
        "pytest completed successfully"
    )

    assert result == "pytest completed successfully"


def test_redact_password(guard):
    result = guard.redact(
        "password=super-secret-value"
    )

    assert result == "password=[REDACTED]"
    assert "super-secret-value" not in result


def test_redact_bearer_token(guard):
    result = guard.redact(
        "Bearer ABCDEFGHIJKLMNOP"
    )

    assert result == "Bearer [REDACTED]"
    assert "ABCDEFGHIJKLMNOP" not in result


def test_redact_private_key(guard):
    result = guard.redact(
        "-----BEGIN PRIVATE KEY-----"
    )

    assert result == "[REDACTED PRIVATE KEY]"


def test_sensitive_environment_name_is_blocked(guard):
    with pytest.raises(SecretExposureError):
        guard.validate_environment(
            {
                "API_KEY": "secret-value"
            }
        )


def test_password_environment_name_is_blocked(guard):
    with pytest.raises(SecretExposureError):
        guard.validate_environment(
            {
                "PASSWORD": "secret-value"
            }
        )


def test_normal_environment_is_allowed(guard):
    guard.validate_environment(
        {
            "APP_MODE": "test",
            "LOG_LEVEL": "INFO",
        }
    )


def test_secret_value_in_environment_is_blocked(guard):
    with pytest.raises(SecretExposureError):
        guard.validate_environment(
            {
                "APP_MODE": "password=secret-value",
            }
        )


def test_non_string_scan_value_is_rejected(guard):
    with pytest.raises(TypeError):
        guard.scan(123)


def test_non_dictionary_environment_is_rejected(guard):
    with pytest.raises(TypeError):
        guard.validate_environment([])
