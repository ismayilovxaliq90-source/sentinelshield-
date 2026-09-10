from __future__ import annotations

import pytest

from sentinelshield.command_allowlist_validation import (
    DEFAULT_ALLOWED_EXECUTABLES,
    CommandAllowlistError,
    CommandAllowlistPolicy,
    require_allowed_command,
    validate_command_allowlist,
)


def test_default_policy_contains_required_execution_tools():
    required = {
        "python",
        "python3",
        "node",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "go",
        "cargo",
        "rustc",
        "mvn",
        "gradle",
        "composer",
        "dotnet",
        "git",
    }

    assert required.issubset(DEFAULT_ALLOWED_EXECUTABLES)


@pytest.mark.parametrize(
    "command",
    [
        ["python"],
        ["python", "-m", "pytest"],
        ["python3"],
        ["node", "--version"],
        ["npm", "--version"],
        ["git", "status"],
    ],
)
def test_allowlisted_executable_is_allowed(command):
    result = validate_command_allowlist(command)

    assert result.allowed is True
    assert result.executable == command[0]
    assert result.reason == "EXECUTABLE_ALLOWLISTED"


@pytest.mark.parametrize(
    "command",
    [
        ["curl"],
        ["wget"],
        ["bash"],
        ["sh"],
        ["zsh"],
        ["rm"],
        ["chmod"],
        ["chown"],
        ["sudo"],
        ["su"],
        ["unknown-tool"],
    ],
)
def test_non_allowlisted_executable_is_rejected(command):
    result = validate_command_allowlist(command)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWLISTED"


def test_string_command_is_rejected():
    result = validate_command_allowlist(
        "python -m pytest"
    )

    assert result.allowed is False
    assert result.reason == "COMMAND_MUST_BE_ARGUMENT_SEQUENCE"


@pytest.mark.parametrize(
    "command",
    [
        [],
        (),
    ],
)
def test_empty_command_is_rejected(command):
    result = validate_command_allowlist(command)

    assert result.allowed is False
    assert result.reason == "COMMAND_IS_EMPTY"


@pytest.mark.parametrize(
    "command",
    [
        [None],
        [123],
        [b"python"],
        [True],
    ],
)
def test_invalid_executable_type_is_rejected(command):
    result = validate_command_allowlist(command)

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_TYPE_INVALID"


@pytest.mark.parametrize(
    "executable",
    [
        "",
        " ",
        " python",
        "python ",
        "python\t",
        "python\n",
    ],
)
def test_invalid_executable_whitespace_is_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.allowed is False


@pytest.mark.parametrize(
    "executable",
    [
        "/usr/bin/python",
        "./python",
        "../python",
        r"C:\Python\python.exe",
        r"..\python",
    ],
)
def test_executable_paths_are_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.allowed is False


@pytest.mark.parametrize(
    "executable",
    [
        "python;rm",
        "python&&rm",
        "python|rm",
        "python>file",
        "python<file",
        "python`id`",
        "python$(id)",
        "python(test)",
        "python{test}",
        "python[test]",
        "python'bad'",
        'python"bad"',
    ],
)
def test_shell_metacharacters_are_rejected(executable):
    result = validate_command_allowlist([executable])

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_TOKEN_INVALID"


def test_null_character_is_rejected():
    result = validate_command_allowlist(["python\x00evil"])

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_TOKEN_INVALID"


def test_arguments_are_not_interpreted_by_allowlist():
    result = validate_command_allowlist(
        [
            "python",
            "-c",
            "print('not executed') && rm -rf /",
        ]
    )

    assert result.allowed is True
    assert result.executable == "python"


def test_argument_validation_is_deferred_to_task_189():
    result = validate_command_allowlist(
        [
            "python",
            "../../../anything",
        ]
    )

    assert result.allowed is True
    assert result.reason == "EXECUTABLE_ALLOWLISTED"


def test_custom_policy_is_supported():
    policy = CommandAllowlistPolicy(
        allowed_executables=frozenset({"python"})
    )

    assert validate_command_allowlist(
        ["python"],
        policy,
    ).allowed is True

    assert validate_command_allowlist(
        ["node"],
        policy,
    ).allowed is False


def test_custom_policy_is_exact():
    policy = CommandAllowlistPolicy(
        allowed_executables=frozenset({"python"})
    )

    result = validate_command_allowlist(
        ["Python"],
        policy,
    )

    assert result.allowed is False
    assert result.reason == "EXECUTABLE_NOT_ALLOWLISTED"


@pytest.mark.parametrize(
    "allowed",
    [
        set(["python"]),
        ["python"],
        ("python",),
        "python",
    ],
)
def test_policy_requires_frozenset(allowed):
    with pytest.raises(TypeError):
        CommandAllowlistPolicy(
            allowed_executables=allowed
        )


@pytest.mark.parametrize(
    "allowed",
    [
        frozenset(),
        frozenset({""}),
        frozenset({"python "}),
        frozenset({"python\n"}),
        frozenset({"/usr/bin/python"}),
        frozenset({"Python"}),
        frozenset({"python;rm"}),
    ],
)
def test_invalid_policy_entries_are_rejected(allowed):
    with pytest.raises(CommandAllowlistError):
        CommandAllowlistPolicy(
            allowed_executables=allowed
        )


def test_require_allowed_command_returns_result():
    result = require_allowed_command(
        ["python", "--version"]
    )

    assert result.allowed is True
    assert result.executable == "python"


def test_require_allowed_command_rejects_unknown_command():
    with pytest.raises(CommandAllowlistError):
        require_allowed_command(["curl", "https://example.com"])


def test_result_to_dict_is_stable():
    result = validate_command_allowlist(
        ["python", "--version"]
    )

    data = result.to_dict()

    assert data["allowed"] is True
    assert data["executable"] == "python"
    assert data["reason"] == "EXECUTABLE_ALLOWLISTED"
    assert "python" in data["policy"]["allowed_executables"]


def test_allowlist_validation_does_not_execute_command():
    # A malicious-looking argument must remain data.
    result = validate_command_allowlist(
        [
            "python",
            "-c",
            "raise SystemExit('THIS MUST NOT RUN')",
        ]
    )

    assert result.allowed is True
    assert result.executable == "python"
