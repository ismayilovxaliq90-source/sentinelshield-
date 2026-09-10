from __future__ import annotations

import pytest

from sentinelshield.command_argument_validation import (
    CommandArgumentPolicy,
    CommandArgumentValidationError,
    require_valid_command_arguments,
    validate_command_arguments,
    validate_command_vector,
)


def test_valid_arguments_are_accepted():
    result = validate_command_arguments(
        "python3",
        ["-m", "pytest", "-q"],
    )

    assert result.allowed is True
    assert result.command == "python3"
    assert result.arguments == ("-m", "pytest", "-q")
    assert result.reason == "COMMAND_ARGUMENTS_VALID"
    assert result.rejected_index is None


def test_command_string_is_not_shell_parsed():
    result = validate_command_arguments(
        "python3 -m pytest",
        ["-q"],
    )

    assert result.allowed is True
    assert result.command == "python3 -m pytest"


@pytest.mark.parametrize(
    "value",
    [
        "foo;bar",
        "foo&&bar",
        "foo||bar",
        "foo|bar",
        "foo`bar`",
        "$(id)",
        "${HOME}",
        "foo>bar",
        "foo<bar",
        "foo>>bar",
        "foo<<bar",
    ],
)
def test_shell_injection_syntax_is_rejected(value):
    result = validate_command_arguments("python3", [value])

    assert result.allowed is False
    assert result.reason == "SHELL_SYNTAX_NOT_ALLOWED"


@pytest.mark.parametrize(
    "value",
    [
        "foo\nbar",
        "foo\rbar",
        "foo\tbar",
        "foo\x01bar",
        "foo\x1fbar",
        "foo\x7fbar",
    ],
)
def test_control_characters_are_rejected(value):
    result = validate_command_arguments("python3", [value])

    assert result.allowed is False
    assert result.reason == "CONTROL_CHARACTER_NOT_ALLOWED"


def test_null_character_is_rejected():
    result = validate_command_arguments(
        "python3",
        ["safe\x00evil"],
    )

    assert result.allowed is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_empty_argument_is_rejected_by_default():
    result = validate_command_arguments("python3", [""])

    assert result.allowed is False
    assert result.reason == "EMPTY_ARGUMENT_NOT_ALLOWED"


def test_empty_argument_can_be_explicitly_allowed():
    policy = CommandArgumentPolicy(
        allow_empty_arguments=True,
    )

    result = validate_command_arguments(
        "python3",
        [""],
        policy,
    )

    assert result.allowed is True


def test_argument_length_limit_is_enforced():
    policy = CommandArgumentPolicy(
        max_argument_length=4,
    )

    result = validate_command_arguments(
        "python3",
        ["12345"],
        policy,
    )

    assert result.allowed is False
    assert result.reason == "ARGUMENT_TOO_LONG"
    assert result.rejected_index == 0


def test_argument_count_limit_is_enforced():
    policy = CommandArgumentPolicy(
        max_arguments=2,
    )

    result = validate_command_arguments(
        "python3",
        ["one", "two", "three"],
        policy,
    )

    assert result.allowed is False
    assert result.reason == "TOO_MANY_ARGUMENTS"
    assert result.argument_count == 3


@pytest.mark.parametrize(
    "argument",
    [
        "../secret",
        "..\\secret",
        "safe/../secret",
        "safe\\..\\secret",
        "../",
        "..\\",
    ],
)
def test_path_traversal_is_rejected(argument):
    result = validate_command_arguments(
        "python3",
        [argument],
    )

    assert result.allowed is False
    assert result.reason == "PATH_TRAVERSAL_NOT_ALLOWED"


def test_normal_relative_path_without_traversal_is_allowed():
    result = validate_command_arguments(
        "python3",
        ["tests/test_example.py"],
    )

    assert result.allowed is True


def test_absolute_path_is_not_automatically_rejected():
    result = validate_command_arguments(
        "python3",
        ["/workspace/project/file.py"],
    )

    assert result.allowed is True


@pytest.mark.parametrize(
    "command",
    [
        "",
        "python3;id",
        "python3&&id",
        "$(id)",
        "python3\nid",
        "python3\x00id",
    ],
)
def test_invalid_command_is_rejected(command):
    result = validate_command_arguments(
        command,
        [],
    )

    assert result.allowed is False


@pytest.mark.parametrize(
    "arguments",
    [
        None,
        "not-a-list",
        b"bytes",
        bytearray(b"bytes"),
    ],
)
def test_invalid_argument_container_is_rejected(arguments):
    result = validate_command_arguments(
        "python3",
        arguments,
    )

    assert result.allowed is False


@pytest.mark.parametrize(
    "argument",
    [
        None,
        1,
        True,
        b"bytes",
        object(),
    ],
)
def test_non_string_argument_is_rejected(argument):
    result = validate_command_arguments(
        "python3",
        [argument],
    )

    assert result.allowed is False
    assert result.reason == "ARGUMENT_NOT_STRING"


def test_command_vector_is_supported():
    result = validate_command_vector(
        ("python3", "-m", "pytest", "-q"),
    )

    assert result.allowed is True
    assert result.command == "python3"
    assert result.arguments == ("-m", "pytest", "-q")


def test_command_vector_string_is_rejected():
    result = validate_command_vector("python3 -m pytest")

    assert result.allowed is False
    assert result.reason == "COMMAND_VECTOR_MUST_BE_SEQUENCE"


def test_empty_command_vector_is_rejected():
    result = validate_command_vector(())

    assert result.allowed is False
    assert result.reason == "COMMAND_VECTOR_EMPTY"


def test_command_vector_argument_injection_is_rejected():
    result = validate_command_vector(
        ("python3", "-m", "pytest;id"),
    )

    assert result.allowed is False
    assert result.reason == "SHELL_SYNTAX_NOT_ALLOWED"


def test_result_to_dict():
    result = validate_command_arguments(
        "python3",
        ["-m", "pytest"],
    )

    data = result.to_dict()

    assert data["allowed"] is True
    assert data["command"] == "python3"
    assert data["arguments"] == ["-m", "pytest"]
    assert data["argument_count"] == 2


def test_require_valid_arguments_returns_result():
    result = require_valid_command_arguments(
        "python3",
        ["-m", "pytest"],
    )

    assert result.allowed is True


def test_require_valid_arguments_fails_closed():
    with pytest.raises(CommandArgumentValidationError):
        require_valid_command_arguments(
            "python3",
            ["$(id)"],
        )


def test_custom_policy_can_disable_path_traversal_check():
    policy = CommandArgumentPolicy(
        reject_path_traversal=False,
    )

    result = validate_command_arguments(
        "python3",
        ["../file.py"],
        policy,
    )

    assert result.allowed is True


def test_policy_rejects_boolean_max_arguments():
    with pytest.raises(TypeError):
        CommandArgumentPolicy(max_arguments=True)


def test_policy_rejects_boolean_max_argument_length():
    with pytest.raises(TypeError):
        CommandArgumentPolicy(max_argument_length=False)


def test_policy_rejects_invalid_limits():
    with pytest.raises(CommandArgumentValidationError):
        CommandArgumentPolicy(max_arguments=0)

    with pytest.raises(CommandArgumentValidationError):
        CommandArgumentPolicy(max_argument_length=0)


def test_policy_rejects_non_boolean_flags():
    with pytest.raises(TypeError):
        CommandArgumentPolicy(allow_empty_arguments=1)

    with pytest.raises(TypeError):
        CommandArgumentPolicy(reject_path_traversal=1)
