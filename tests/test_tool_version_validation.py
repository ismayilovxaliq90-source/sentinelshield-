from subprocess import CalledProcessError, TimeoutExpired
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


def test_single_valid_tool():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.11.1\n"),
    ):
        request = ToolVersionValidationInput(
            requirements=(
                ToolVersionRequirement(
                    name="node",
                    min_version="18.0.0",
                ),
            ),
        )

        result = validate_tool_versions(request)

    assert result.valid is True
    assert result.requested_count == 1
    assert result.available_count == 1
    assert result.valid_count == 1
    assert result.invalid_count == 0
    assert result.missing_count == 0
    assert result.reason == "ALL_TOOL_VERSIONS_VALID"

    tool = result.tools[0]

    assert tool.name == "node"
    assert tool.available is True
    assert tool.executable == "/usr/bin/node"
    assert tool.version == "v20.11.1"
    assert tool.normalized_version == (20, 11, 1)
    assert tool.valid is True
    assert tool.reason == "TOOL_VERSION_VALID"


def test_minimum_version_failure():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v16.20.0\n"),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        min_version="18.0.0",
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.invalid_count == 1
    assert result.tools[0].reason == (
        "VERSION_BELOW_MINIMUM"
    )


def test_maximum_version_failure():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v24.0.0\n"),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        max_version="22.0.0",
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.invalid_count == 1
    assert result.tools[0].reason == (
        "VERSION_ABOVE_MAXIMUM"
    )


def test_version_boundary_is_inclusive():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.0.0\n"),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        min_version="20.0.0",
                        max_version="20.0.0",
                    ),
                ),
            )
        )

    assert result.valid is True


def test_required_tool_missing():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value=None,
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        required=True,
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.available_count == 0
    assert result.missing_count == 1
    assert result.tools[0].reason == (
        "REQUIRED_TOOL_NOT_FOUND"
    )


def test_optional_tool_missing():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value=None,
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="optional-tool",
                        required=False,
                    ),
                ),
            )
        )

    assert result.valid is True
    assert result.missing_count == 1
    assert result.tools[0].valid is True
    assert result.tools[0].reason == (
        "OPTIONAL_TOOL_NOT_FOUND"
    )


def test_multiple_tools():
    paths = {
        "node": "/usr/bin/node",
        "npm": "/usr/bin/npm",
        "git": "/usr/bin/git",
    }

    versions = {
        "/usr/bin/node": "v20.11.1\n",
        "/usr/bin/npm": "10.9.2\n",
        "/usr/bin/git": "git version 2.43.0\n",
    }

    def which(name):
        return paths.get(name)

    def run(command, **kwargs):
        return completed(versions[command[0]])

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        side_effect=which,
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=run,
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        min_version="18.0.0",
                    ),
                    ToolVersionRequirement(
                        name="npm",
                        min_version="9.0.0",
                    ),
                    ToolVersionRequirement(
                        name="git",
                        min_version="2.0.0",
                    ),
                ),
            )
        )

    assert result.valid is True
    assert result.requested_count == 3
    assert result.available_count == 3
    assert result.valid_count == 3


def test_version_command_failure():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=CalledProcessError(
            1,
            ["/usr/bin/node", "--version"],
        ),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.tools[0].reason == (
        "VERSION_COMMAND_FAILED"
    )


def test_version_command_timeout():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        side_effect=TimeoutExpired(
            ["/usr/bin/node", "--version"],
            10,
        ),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.tools[0].reason == (
        "VERSION_COMMAND_TIMEOUT"
    )


def test_empty_version_output():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed(""),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                    ),
                ),
            )
        )

    assert result.valid is False
    assert result.tools[0].reason == (
        "VERSION_OUTPUT_EMPTY"
    )


def test_stderr_version_output_is_supported():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/git",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed(
            "",
            "2.43.0\n",
        ),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="git",
                        min_version="2.0.0",
                    ),
                ),
            )
        )

    assert result.valid is True
    assert result.tools[0].version == "2.43.0"


def test_requirement_type_validation():
    with pytest.raises(TypeError):
        validate_tool_versions(
            ToolVersionValidationInput(
                requirements=("node",),
            )
        )


def test_empty_requirements_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="REQUIREMENTS_ARE_EMPTY",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(),
            )
        )


def test_empty_tool_name_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="TOOL_NAME_IS_EMPTY",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="   ",
                    ),
                ),
            )
        )


def test_duplicate_tool_requirement_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="DUPLICATE_TOOL_REQUIREMENT",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(name="node"),
                    ToolVersionRequirement(name="NODE"),
                ),
            )
        )


def test_invalid_version_format():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("not-a-version\n"),
    ):
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(name="node"),
                ),
            )
        )

    assert result.valid is False
    assert result.tools[0].reason == (
        "INVALID_VERSION_FORMAT"
    )


def test_maximum_below_minimum_rejected():
    with pytest.raises(
        ToolVersionValidationError,
        match="MAX_VERSION_MUST_NOT_BE_LESS",
    ):
        validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                        min_version="20.0.0",
                        max_version="18.0.0",
                    ),
                ),
            )
        )


def test_duplicate_input_not_mutated():
    requirements = (
        ToolVersionRequirement(
            name=" node ",
            min_version="18.0.0",
        ),
    )

    original = ToolVersionValidationInput(
        requirements=requirements,
    )

    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.0.0\n"),
    ):
        result = validate_tool_versions(original)

    assert original.requirements == requirements
    assert result.tools[0].name == "node"


def test_aliases():
    request = ToolVersionValidationInput(
        requirements=(
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
    ):
        first = validate_tool_versions(request)
        second = tool_version_validation(request)
        third = check_tool_versions(request)

    assert first == second == third
    assert are_tool_versions_valid(request) is True


def test_version_command_uses_double_dash_version():
    with patch(
        "sentinelshield.tool_version_validation.shutil.which",
        return_value="/usr/bin/node",
    ), patch(
        "sentinelshield.tool_version_validation.subprocess.run",
        return_value=completed("v20.0.0\n"),
    ) as mock_run:
        result = validate_tool_versions(
            ToolVersionValidationInput(
                requirements=(
                    ToolVersionRequirement(
                        name="node",
                    ),
                ),
            )
        )

    assert result.valid is True
    assert mock_run.call_args.args[0] == [
        "/usr/bin/node",
        "--version",
    ]
