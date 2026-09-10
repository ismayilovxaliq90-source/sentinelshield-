from unittest.mock import patch

import pytest

from sentinelshield.tool_version_validation import (
    ToolVersionRequirement,
    ToolVersionValidationError,
    ToolVersionValidationInput,
    are_tool_versions_valid,
    check_tool_versions,
    tool_version_validation,
    validate_tool_versions,
)


def completed(stdout="", stderr=""):
    return type(
        "Completed",
        (),
        {
            "stdout": stdout,
            "stderr": stderr,
        },
    )()


def test_valid_tool_version():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                min_version="18.0.0",
                max_version="24.99.99",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.11.1\n"),
    ):
        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.available_count == 1
    assert result.compatible_count == 1
    assert result.missing_count == 0
    assert result.incompatible_count == 0
    assert result.reason == "ALL_REQUIRED_TOOL_VERSIONS_VALID"

    item = result.tools[0]

    assert item.name == "node"
    assert item.available is True
    assert item.executable == "/usr/bin/node"
    assert item.version == "v20.11.1"
    assert item.version_tuple == (20, 11, 1)
    assert item.compatible is True
    assert item.reason == "TOOL_VERSION_COMPATIBLE"


def test_missing_required_tool_fails():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                min_version="18.0.0",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value=None,
    ):
        result = validate_tool_versions(request)

    assert result.valid is False
    assert result.available_count == 0
    assert result.missing_count == 1
    assert result.incompatible_count == 0
    assert result.tools[0].reason == "TOOL_NOT_FOUND"


def test_missing_optional_tool_does_not_fail():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="yarn",
                required=False,
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value=None,
    ):
        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.missing_count == 1
    assert result.reason == "ALL_REQUIRED_TOOL_VERSIONS_VALID"


def test_version_below_minimum_fails():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                min_version="20.0.0",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v18.20.0\n"),
    ):
        result = validate_tool_versions(request)

    assert result.valid is False
    assert result.incompatible_count == 1
    assert result.tools[0].compatible is False
    assert result.tools[0].reason == (
        "TOOL_VERSION_INCOMPATIBLE"
    )


def test_version_above_maximum_fails():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                max_version="20.99.99",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v22.0.0\n"),
    ):
        result = validate_tool_versions(request)

    assert result.valid is False
    assert result.incompatible_count == 1


def test_exact_minimum_is_allowed():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                min_version="20.11.1",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.11.1\n"),
    ):
        result = validate_tool_versions(request)

    assert result.valid is True


def test_exact_maximum_is_allowed():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                max_version="20.11.1",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.11.1\n"),
    ):
        result = validate_tool_versions(request)

    assert result.valid is True


def test_multiple_tools():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
                min_version="18.0.0",
            ),
            ToolVersionRequirement(
                name="npm",
                min_version="9.0.0",
            ),
        ),
    )

    paths = {
        "node": "/usr/bin/node",
        "npm": "/usr/bin/npm",
    }

    def which(name):
        return paths[name]

    def run(command, **kwargs):
        if command[0] == "/usr/bin/node":
            return completed("v20.11.1\n")
        return completed("10.9.2\n")

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        side_effect=which,
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=run,
    ):
        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.total_count == 2
    assert result.available_count == 2
    assert result.compatible_count == 2


def test_version_command_uses_double_dash_version():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="node",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.0.0\n"),
    ) as mock_run:
        result = validate_tool_versions(request)

    assert result.valid is True
    assert mock_run.call_args.args[0] == [
        "/usr/bin/node",
        "--version",
    ]


def test_version_output_with_prefix():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="git",
                min_version="2.0.0",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/git",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed(
            "git version 2.50.1\n"
        ),
    ):
        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.tools[0].version_tuple == (
        2,
        50,
        1,
    )


def test_stderr_version_output():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement(
                name="tool",
            ),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/tool",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed(
            stdout="",
            stderr="v1.2.3\n",
        ),
    ):
        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.tools[0].version_tuple == (
        1,
        2,
        3,
    )


def test_invalid_input_type():
    with pytest.raises(TypeError):
        validate_tool_versions("invalid")


def test_empty_tools_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="TOOL_REQUIREMENT_LIST_IS_EMPTY",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(),
            )
        )


def test_duplicate_tools_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="DUPLICATE_TOOL_REQUIREMENT",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(
                    ToolVersionRequirement("node"),
                    ToolVersionRequirement("NODE"),
                ),
            )
        )


def test_invalid_tool_name():
    with pytest.raises(
        ToolVersionValidationError,
        match="INVALID_TOOL_NAME",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(
                    ToolVersionRequirement(
                        "node tool"
                    ),
                ),
            )
        )


def test_minimum_greater_than_maximum_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="MIN_VERSION_MUST_NOT_EXCEED_MAX_VERSION",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(
                    ToolVersionRequirement(
                        "node",
                        min_version="22.0.0",
                        max_version="20.0.0",
                    ),
                ),
            )
        )


def test_invalid_timeout():
    with pytest.raises(
        ToolVersionValidationError,
        match="TIMEOUT_MUST_BE",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(
                    ToolVersionRequirement("node"),
                ),
                timeout_seconds=0,
            )
        )


def test_required_must_be_boolean():
    with pytest.raises(TypeError):
        validate_tool_versions(
            ToolVersionValidationInput(
                tools=(
                    ToolVersionRequirement(
                        "node",
                        required="yes",
                    ),
                ),
            )
        )


def test_version_command_failure():
    from subprocess import CalledProcessError

    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement("node"),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=CalledProcessError(
            returncode=1,
            cmd=["/usr/bin/node", "--version"],
        ),
    ):
        result = validate_tool_versions(request)

    assert result.valid is False
    assert result.tools[0].reason == (
        "VERSION_COMMAND_FAILED"
    )


def test_version_command_timeout():
    from subprocess import TimeoutExpired

    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement("node"),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=TimeoutExpired(
            cmd=["/usr/bin/node", "--version"],
            timeout=10,
        ),
    ):
        result = validate_tool_versions(request)

    assert result.valid is False
    assert result.tools[0].reason == (
        "VERSION_COMMAND_TIMEOUT"
    )


def test_public_aliases():
    request = ToolVersionValidationInput(
        tools=(
            ToolVersionRequirement("node"),
        ),
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.0.0\n"),
    ):
        first = validate_tool_versions(request)
        second = tool_version_validation(request)
        third = check_tool_versions(request)

        assert first == second == third
        assert are_tool_versions_valid(request) is True
