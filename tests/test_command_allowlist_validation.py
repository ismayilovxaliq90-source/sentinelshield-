import pytest

from sentinelshield.command_allowlist_validation import (
    CommandAllowlistError,
    CommandAllowlistPolicy,
    require_allowed_command,
    validate_command_allowlist,
)


def test_allowed_executable():
    policy = CommandAllowlistPolicy({"git", "python"})
    result = validate_command_allowlist(["git", "status"], policy)

    assert result.allowed is True
    assert result.executable == "git"
    assert result.reason == "COMMAND_ALLOWED"


def test_denied_executable():
    policy = CommandAllowlistPolicy({"git"})
    result = validate_command_allowlist(["rm", "-rf", "/tmp/x"], policy)

    assert result.allowed is False
    assert result.executable == "rm"
    assert result.reason == "EXECUTABLE_NOT_ALLOWED"


def test_string_command_is_rejected():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist("git status", policy)


def test_bytes_command_is_rejected():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(b"git status", policy)


def test_empty_command_is_rejected():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist([], policy)


def test_non_string_argument_is_rejected():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(["git", 123], policy)


def test_null_character_is_rejected():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(["git\x00evil"], policy)


@pytest.mark.parametrize(
    "command",
    [
        ["/usr/bin/git", "status"],
        ["./git", "status"],
        ["../git", "status"],
        ["foo/bar", "status"],
        [r"foo\bar", "status"],
    ],
)
def test_path_qualified_executable_is_rejected(command):
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(command, policy)


@pytest.mark.parametrize(
    "command",
    [
        ["git;rm"],
        ["git|rm"],
        ["git&&rm"],
        ["git$(id)"],
        ["git`id`"],
        ["git>file"],
        ["git\nrm"],
    ],
)
def test_shell_metacharacters_are_rejected(command):
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(command, policy)


@pytest.mark.parametrize(
    "command",
    [
        ["."],
        [".."],
    ],
)
def test_dot_executable_is_rejected(command):
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        validate_command_allowlist(command, policy)


def test_arguments_do_not_change_executable_allowlist_decision():
    policy = CommandAllowlistPolicy({"git"})

    result = validate_command_allowlist(
        ["git", "status", "--porcelain"],
        policy,
    )

    assert result.allowed is True


def test_default_deny():
    policy = CommandAllowlistPolicy(set())

    result = validate_command_allowlist(["git", "status"], policy)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWED"


def test_allowlist_is_immutable():
    policy = CommandAllowlistPolicy({"git"})

    assert isinstance(policy.allowed_executables, frozenset)

    with pytest.raises(AttributeError):
        policy.allowed_executables.add("python")


@pytest.mark.parametrize(
    "value",
    [
        "",
        " git",
        "git ",
        "foo/bar",
        r"foo\bar",
        "git;rm",
        "git\x00evil",
        ".",
        "..",
    ],
)
def test_invalid_policy_entry_is_rejected(value):
    with pytest.raises(CommandAllowlistError):
        CommandAllowlistPolicy({value})


def test_allowlist_is_case_sensitive():
    policy = CommandAllowlistPolicy({"git"})

    result = validate_command_allowlist(["GIT"], policy)

    assert result.allowed is False


def test_require_allowed_command_returns_result():
    policy = CommandAllowlistPolicy({"git"})

    result = require_allowed_command(["git", "status"], policy)

    assert result.allowed is True


def test_require_allowed_command_rejects():
    policy = CommandAllowlistPolicy({"git"})

    with pytest.raises(CommandAllowlistError):
        require_allowed_command(["rm", "-rf", "/"], policy)
