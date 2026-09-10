from __future__ import annotations

import pytest

from sentinelshield.command_allowlist_validation import (
    CommandAllowlistError,
    CommandAllowlistPolicy,
    DEFAULT_ALLOWED_EXECUTABLES,
    require_allowed_command,
    validate_command_allowlist,
)


def test_allowed_python_command():
    result = validate_command_allowlist(["python", "--version"])

    assert result.valid is True
    assert result.executable == "python"
    assert result.reason is None


def test_allowed_python3_command():
    result = validate_command_allowlist(["python3", "-m", "pytest"])

    assert result.valid is True


def test_all_default_executables_are_allowed():
    for executable in DEFAULT_ALLOWED_EXECUTABLES:
        result = validate_command_allowlist([executable])

        assert result.valid is True
        assert result.executable == executable


def test_command_must_not_be_empty():
    result = validate_command_allowlist([])

    assert result.valid is False
    assert result.reason == "COMMAND_MUST_NOT_BE_EMPTY"


@pytest.mark.parametrize(
    "command",
    [
        "python",
        b"python",
        None,
        123,
    ],
)
def test_command_must_be_sequence(command):
    result = validate_command_allowlist(command)

    assert result.valid is False
    assert result.reason == "COMMAND_MUST_BE_A_SEQUENCE"


@pytest.mark.parametrize(
    "command",
    [
        [None],
        [123],
        [b"python"],
    ],
)
def test_executable_must_be_string(command):
    result = validate_command_allowlist(command)

    assert result.valid is False
    assert result.reason == "EXECUTABLE_MUST_BE_STRING"


def test_empty_executable_is_rejected():
    result = validate_command_allowlist([""])

    assert result.valid is False
    assert result.reason == "EXECUTABLE_MUST_NOT_BE_EMPTY"


@pytest.mark.parametrize(
    "executable",
    [
        "unknown-command",
        "bash",
        "sh",
        "powershell",
    ],
)
def test_executable_must_be_allowlisted(executable):
    result = validate_command_allowlist([executable])

    assert result.valid is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWED"


@pytest.mark.parametrize(
    "executable",
    [
        "/usr/bin/python",
        "./python",
        "../python",
        r"C:\Python\python.exe",
        r"bin\python",
    ],
)
def test_executable_path_is_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.valid is False
    assert result.reason == "EXECUTABLE_PATH_NOT_ALLOWED"


@pytest.mark.parametrize(
    "executable",
    [
        "python;rm",
        "python && rm",
        "python|rm",
        "python`rm`",
        "python$HOME",
        "python>file",
        "python<file",
    ],
)
def test_shell_metacharacters_are_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.valid is False
    assert result.reason == "SHELL_METACHARACTER_NOT_ALLOWED"


def test_null_character_is_rejected():
    result = validate_command_allowlist(["python\x00evil"])

    assert result.valid is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


@pytest.mark.parametrize(
    "executable",
    [
        "python\n",
        "python\r",
        "python\t",
        "python\x7f",
    ],
)
def test_control_character_is_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.valid is False
    assert result.reason == "CONTROL_CHARACTER_NOT_ALLOWED"


def test_arguments_are_not_validated_by_task_188():
    result = validate_command_allowlist(
        ["python", "some;argument", "--unsafe-looking-argument"]
    )

    assert result.valid is True


def test_custom_policy():
    policy = CommandAllowlistPolicy(
        allowed_executables=frozenset({"custom-tool"})
    )

    assert validate_command_allowlist(
        ["custom-tool"],
        policy,
    ).valid is True

    assert validate_command_allowlist(
        ["python"],
        policy,
    ).valid is False


def test_require_allowed_command_accepts_valid_command():
    require_allowed_command(["python", "--version"])


def test_require_allowed_command_rejects_invalid_command():
    with pytest.raises(CommandAllowlistError):
        require_allowed_command(["bash"])
