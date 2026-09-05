import pytest

from sentinelshield.environment_validator import (
    EnvironmentVariableValidationError,
    EnvironmentVariableValidator,
)


@pytest.fixture
def validator():
    return EnvironmentVariableValidator()


def test_safe_environment_is_allowed(validator):
    result = validator.validate(
        {
            "APP_MODE": "test",
            "LOG_LEVEL": "INFO",
        }
    )

    assert result.values == {
        "APP_MODE": "test",
        "LOG_LEVEL": "INFO",
    }


def test_empty_environment_is_allowed(validator):
    result = validator.validate({})

    assert result.values == {}


def test_environment_must_be_dictionary(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate([])


def test_non_string_name_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({123: "value"})


def test_non_string_value_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"APP_MODE": 123})


def test_empty_name_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"": "value"})


def test_invalid_name_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"APP-MODE": "test"})


def test_name_starting_with_number_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"123MODE": "test"})


def test_ld_preload_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"LD_PRELOAD": "/tmp/lib.so"})


def test_ld_library_path_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"LD_LIBRARY_PATH": "/tmp"})


def test_pythonpath_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"PYTHONPATH": "/tmp"})


def test_pythonhome_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"PYTHONHOME": "/tmp"})


def test_bash_env_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"BASH_ENV": "/tmp/file"})


def test_nul_byte_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"APP_MODE": "test\x00value"})


def test_newline_is_blocked(validator):
    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"APP_MODE": "test\nvalue"})


def test_value_length_limit_is_enforced(validator):
    value = "x" * (
        EnvironmentVariableValidator.MAX_VALUE_LENGTH + 1
    )

    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({"APP_MODE": value})


def test_name_length_limit_is_enforced(validator):
    name = "A" * (
        EnvironmentVariableValidator.MAX_NAME_LENGTH + 1
    )

    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate({name: "test"})


def test_variable_count_limit_is_enforced(validator):
    environment = {
        f"VAR_{index}": "value"
        for index in range(
            EnvironmentVariableValidator.MAX_VARIABLES + 1
        )
    }

    with pytest.raises(EnvironmentVariableValidationError):
        validator.validate(environment)


def test_is_safe_returns_true_for_safe_environment(validator):
    assert validator.is_safe(
        {"APP_MODE": "test"}
    ) is True


def test_is_safe_returns_false_for_unsafe_environment(validator):
    assert validator.is_safe(
        {"PYTHONPATH": "/tmp"}
    ) is False
