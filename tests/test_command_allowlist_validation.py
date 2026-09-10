from __future__ import annotations

import pytest

from sentinelshield.command_allowlist_validation import (
    CommandAllowlistError,
    CommandAllowlistPolicy,
    require_allowed_command,
    validate_command_allowlist,
)


@pytest.fixture
def policy() -> CommandAllowlistPolicy:
    return CommandAllowlistPolicy.from_iterable(
        {"git", "python3", "node"}
    )


def test_allowed_executable_passes(policy):
    result = validate_command_allowlist(["git", "status"], policy)

    assert result.allowed is True
    assert result.executable == "git"
    assert result.reason == "EXECUTABLE_ALLOWLISTED"
    assert result.command_length == 2


def test_another_allowed_executable_passes(policy):
    result = validate_command_allowlist(["python3", "--version"], policy)

    assert result.allowed is True
    assert result.executable == "python3"


def test_non_allowlisted_executable_fails(policy):
    result = validate_command_allowlist(["curl", "https://example.com"], policy)

    assert result.allowed is False
    assert result.executable == "curl"
    assert result.reason == "EXECUTABLE_NOT_ALLOWLISTED"


def test_command_string_is_rejected(policy):
    result = validate_command_allowlist("git status", policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_MUST_BE_SEQUENCE"


def test_bytes_command_is_rejected(policy):
    result = validate_command_allowlist(b"git status", policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_MUST_BE_SEQUENCE"


def test_empty_command_is_rejected(policy):
    result = validate_command_allowlist([], policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_IS_EMPTY"


def test_non_sequence_command_is_rejected(policy):
    result = validate_command_allowlist(None, policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_MUST_BE_SEQUENCE"


def test_non_string_argument_is_rejected(policy):
    result = validate_command_allowlist(["git", 123], policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_ELEMENT_MUST_BE_STRING"


def test_empty_command_element_is_rejected(policy):
    result = validate_command_allowlist(["git", ""], policy)

    assert result.allowed is False
    assert result.reason == "COMMAND_ELEMENT_IS_EMPTY"


def test_null_character_is_rejected(policy):
    result = validate_command_allowlist(["git\x00evil"], policy)

    assert result.allowed is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


@pytest.mark.parametrize(
    "command",
    [
        ["/usr/bin/git", "status"],
        ["./git", "status"],
        ["../git", "status"],
        ["bin/git", "status"],
        [r"bin\git", "status"],
    ],
)
def test_path_qualified_executable_is_rejected(policy, command):
    result = validate_command_allowlist(command, policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_PATH_NOT_ALLOWED"


@pytest.mark.parametrize(
    "command",
    [
        ["git;rm", "-rf"],
        ["git|cat"],
        ["git&&cat"],
        ["git>output"],
        ["git`id`"],
        ["git$(id)"],
        ["git\nstatus"],
        ["git\rstatus"],
    ],
)
def test_shell_syntax_in_executable_is_rejected(policy, command):
    result = validate_command_allowlist(command, policy)

    assert result.allowed is False


def test_executable_whitespace_is_rejected(policy):
    result = validate_command_allowlist([" git"], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_WHITESPACE_NOT_ALLOWED"


def test_trailing_executable_whitespace_is_rejected(policy):
    result = validate_command_allowlist(["git "], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_WHITESPACE_NOT_ALLOWED"


def test_dot_executable_is_rejected(policy):
    result = validate_command_allowlist(["."], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_PATH_NOT_ALLOWED"


def test_dotdot_executable_is_rejected(policy):
    result = validate_command_allowlist([".."], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_PATH_NOT_ALLOWED"


def test_argument_content_is_not_mistaken_for_executable_policy(policy):
    result = validate_command_allowlist(
        ["git", "status", "--porcelain"],
        policy,
    )

    assert result.allowed is True


def test_argument_shell_text_does_not_change_executable_allowlist_result(policy):
    """
    Task 188 validates the executable only.
    Detailed argument restrictions belong to Task 189.
    """
    result = validate_command_allowlist(
        ["git", "status; echo forbidden"],
        policy,
    )

    assert result.allowed is True
    assert result.executable == "git"


def test_default_deny_requires_explicit_policy():
    policy = CommandAllowlistPolicy.from_iterable(set())

    result = validate_command_allowlist(["git", "status"], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWLISTED"


def test_policy_rejects_string_as_allowlist():
    with pytest.raises(TypeError):
        CommandAllowlistPolicy.from_iterable("git")


def test_policy_rejects_bytes_as_allowlist():
    with pytest.raises(TypeError):
        CommandAllowlistPolicy.from_iterable(b"git")


def test_policy_rejects_empty_allowlist_entry():
    with pytest.raises(CommandAllowlistError):
        CommandAllowlistPolicy.from_iterable({"git", ""})


def test_policy_rejects_path_allowlist_entry():
    with pytest.raises(CommandAllowlistError):
        CommandAllowlistPolicy.from_iterable({"/usr/bin/git"})


def test_policy_rejects_shell_syntax():
    with pytest.raises(CommandAllowlistError):
        CommandAllowlistPolicy.from_iterable({"git;rm"})


def test_require_allowed_command_passes(policy):
    result = require_allowed_command(["git", "status"], policy)

    assert result.allowed is True
    assert result.executable == "git"


def test_require_allowed_command_fails_closed(policy):
    with pytest.raises(CommandAllowlistError):
        require_allowed_command(["curl"], policy)


def test_result_to_dict(policy):
    result = validate_command_allowlist(["git"], policy)

    data = result.to_dict()

    assert data == {
        "allowed": True,
        "executable": "git",
        "reason": "EXECUTABLE_ALLOWLISTED",
        "command_length": 1,
    }


def test_allowlist_is_immutable():
    policy = CommandAllowlistPolicy.from_iterable({"git"})

    with pytest.raises(AttributeError):
        policy.allowed_commands.add("curl")


def test_allowlist_matching_is_case_sensitive(policy):
    result = validate_command_allowlist(["Git"], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWLISTED"


def test_no_command_execution_is_performed(policy):
    """
    The validation API has no execution side effect.
    A harmless-looking command is still only inspected.
    """
    result = validate_command_allowlist(
        ["python3", "-c", "raise SystemExit(99)"],
        policy,
    )

    assert result.allowed is True
    assert result.executable == "python3"
