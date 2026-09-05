import pytest

from sentinelshield.argument_validator import (
    ArgumentValidationError,
    ArgumentValidator,
)


@pytest.fixture
def validator():
    return ArgumentValidator()


def test_safe_arguments_are_allowed(validator):
    result = validator.validate(
        ["-m", "pytest", "-q"]
    )

    assert result.values == (
        "-m",
        "pytest",
        "-q",
    )


def test_empty_arguments_are_allowed(validator):
    result = validator.validate([])

    assert result.values == ()


def test_non_string_argument_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["-q", 123])


def test_nul_byte_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["test\x00file"])


def test_shell_separator_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate([";"])


def test_shell_chain_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["&&"])


def test_pipe_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["|"])


def test_redirect_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate([">"])


def test_environment_expansion_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["$HOME"])


def test_home_expansion_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["~/secret"])


def test_newline_is_blocked(validator):
    with pytest.raises(ArgumentValidationError):
        validator.validate(["test\nfile"])


def test_argument_length_limit_is_enforced(validator):
    long_argument = "a" * (
        ArgumentValidator.MAX_ARGUMENT_LENGTH + 1
    )

    with pytest.raises(ArgumentValidationError):
        validator.validate([long_argument])


def test_argument_count_limit_is_enforced(validator):
    arguments = ["x"] * (
        ArgumentValidator.MAX_ARGUMENTS + 1
    )

    with pytest.raises(ArgumentValidationError):
        validator.validate(arguments)


def test_is_safe_returns_true_for_safe_arguments(validator):
    assert validator.is_safe(
        ["-m", "pytest"]
    ) is True


def test_is_safe_returns_false_for_unsafe_arguments(validator):
    assert validator.is_safe(
        ["&&"]
    ) is False
