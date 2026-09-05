import pytest

from sentinelshield.command_validator import (
    CommandValidationError,
    CommandValidator,
)


@pytest.fixture
def validator():
    return CommandValidator()


def test_safe_python_command_is_allowed(validator):
    result = validator.validate("python -m pytest")

    assert result.program == "python"
    assert result.arguments == ("-m", "pytest")
    assert result.argv == ("python", "-m", "pytest")


def test_safe_pytest_command_is_allowed(validator):
    result = validator.validate("pytest -q")

    assert result.program == "pytest"
    assert result.arguments == ("-q",)


def test_empty_command_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("")


def test_unknown_command_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("curl https://example.com")


def test_shell_chain_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("pytest -q && rm -rf /")


def test_pipe_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("pytest -q | cat")


def test_redirect_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("pytest -q > output.txt")


def test_environment_expansion_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("python $HOME/test.py")


def test_home_expansion_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("python ~/test.py")


def test_malformed_command_is_blocked(validator):
    with pytest.raises(CommandValidationError):
        validator.validate("python 'unterminated")


def test_is_safe_returns_true_for_safe_command(validator):
    assert validator.is_safe("pytest -q") is True


def test_is_safe_returns_false_for_unsafe_command(validator):
    assert validator.is_safe("rm -rf /") is False
