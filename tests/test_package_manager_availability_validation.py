from unittest.mock import patch

import pytest

from sentinelshield.package_manager_availability_validation import (
    PackageManagerAvailabilityValidationError,
    PackageManagerAvailabilityValidationInput,
    are_package_managers_available,
    check_package_manager_availability,
    package_manager_availability_validation,
    validate_package_manager_availability,
)


def _completed(stdout: str):
    return type(
        "Completed",
        (),
        {
            "stdout": stdout,
            "stderr": "",
        },
    )()


def test_default_input():
    request = PackageManagerAvailabilityValidationInput()

    assert request.package_managers == ("npm",)
    assert request.require_all is True
    assert request.version_timeout_seconds == 10.0


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value="/usr/bin/npm",
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
    return_value=_completed("10.9.2\n"),
)
def test_single_manager_available(mock_run, mock_which):
    result = validate_package_manager_availability()

    assert result.valid is True
    assert result.requested_count == 1
    assert result.available_count == 1
    assert result.missing_count == 0
    assert result.failed_version_count == 0
    assert result.reason == (
        "ALL_REQUIRED_PACKAGE_MANAGERS_AVAILABLE"
    )

    item = result.package_managers[0]

    assert item.name == "npm"
    assert item.available is True
    assert item.executable == "/usr/bin/npm"
    assert item.version == "10.9.2"
    assert item.reason == "PACKAGE_MANAGER_AVAILABLE"


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value=None,
)
def test_required_manager_missing(mock_which):
    request = PackageManagerAvailabilityValidationInput(
        package_managers=("npm",),
        require_all=True,
    )

    result = validate_package_manager_availability(request)

    assert result.valid is False
    assert result.available_count == 0
    assert result.missing_count == 1
    assert result.reason == "REQUIRED_PACKAGE_MANAGER_MISSING"

    item = result.package_managers[0]

    assert item.available is False
    assert item.executable is None
    assert item.version is None
    assert item.reason == "PACKAGE_MANAGER_NOT_FOUND"


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    side_effect=lambda name: {
        "npm": "/usr/bin/npm",
        "yarn": None,
    }[name],
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
    return_value=_completed("10.9.2\n"),
)
def test_require_all_false_allows_partial_availability(
    mock_run,
    mock_which,
):
    request = PackageManagerAvailabilityValidationInput(
        package_managers=("npm", "yarn"),
        require_all=False,
    )

    result = validate_package_manager_availability(request)

    assert result.valid is True
    assert result.available_count == 1
    assert result.missing_count == 1
    assert result.reason == (
        "ALL_REQUIRED_PACKAGE_MANAGERS_AVAILABLE"
    )


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    side_effect=lambda name: None,
)
def test_require_all_false_still_fails_when_none_available(
    mock_which,
):
    request = PackageManagerAvailabilityValidationInput(
        package_managers=("npm", "yarn"),
        require_all=False,
    )

    result = validate_package_manager_availability(request)

    assert result.valid is False
    assert result.available_count == 0
    assert result.reason == (
        "NO_REQUESTED_PACKAGE_MANAGER_AVAILABLE"
    )


def test_empty_manager_list_rejected():
    with pytest.raises(
        PackageManagerAvailabilityValidationError,
        match="PACKAGE_MANAGER_LIST_IS_EMPTY",
    ):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                package_managers=(),
            )
        )


def test_duplicate_manager_rejected():
    with pytest.raises(
        PackageManagerAvailabilityValidationError,
        match="DUPLICATE_PACKAGE_MANAGER",
    ):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                package_managers=("npm", "npm"),
            )
        )


def test_unsupported_manager_rejected():
    with pytest.raises(
        PackageManagerAvailabilityValidationError,
        match="UNSUPPORTED_PACKAGE_MANAGER",
    ):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                package_managers=("unknown-manager",),
            )
        )


def test_manager_names_are_normalized():
    with patch(
        "sentinelshield.package_manager_availability_validation.shutil.which",
        return_value="/usr/bin/npm",
    ), patch(
        "sentinelshield.package_manager_availability_validation.subprocess.run",
        return_value=_completed("10.9.2\n"),
    ):
        result = validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                package_managers=("  NPM  ",),
            )
        )

    assert result.valid is True
    assert result.package_managers[0].name == "npm"


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -1,
        "10",
    ],
)
def test_invalid_timeout(value):
    with pytest.raises(
        (
            TypeError,
            PackageManagerAvailabilityValidationError,
        )
    ):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                version_timeout_seconds=value,
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        "",
    ],
)
def test_invalid_require_all(value):
    with pytest.raises(TypeError):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                require_all=value,
            )
        )


def test_input_type_validation():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE",
    ):
        validate_package_manager_availability(
            "invalid"
        )


def test_package_managers_must_be_tuple():
    with pytest.raises(
        TypeError,
        match="PACKAGE_MANAGERS_MUST_BE_TUPLE",
    ):
        validate_package_manager_availability(
            PackageManagerAvailabilityValidationInput(
                package_managers=["npm"],
            )
        )


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value="/usr/bin/npm",
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
    return_value=_completed("10.9.2\n"),
)
def test_version_command_uses_double_dash_version(
    mock_run,
    mock_which,
):
    result = validate_package_manager_availability()

    assert result.valid is True

    assert mock_run.call_args.args[0] == [
        "/usr/bin/npm",
        "--version",
    ]


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value="/usr/bin/npm",
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
)
def test_version_command_failure(
    mock_run,
    mock_which,
):
    from subprocess import CalledProcessError

    mock_run.side_effect = CalledProcessError(
        returncode=1,
        cmd=["/usr/bin/npm", "--version"],
    )

    result = validate_package_manager_availability()

    assert result.valid is False
    assert result.failed_version_count == 1
    assert result.package_managers[0].reason == (
        "VERSION_COMMAND_FAILED"
    )


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value="/usr/bin/npm",
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
)
def test_version_command_timeout(
    mock_run,
    mock_which,
):
    from subprocess import TimeoutExpired

    mock_run.side_effect = TimeoutExpired(
        cmd=["/usr/bin/npm", "--version"],
        timeout=10,
    )

    result = validate_package_manager_availability()

    assert result.valid is False
    assert result.failed_version_count == 1
    assert result.package_managers[0].reason == (
        "VERSION_COMMAND_TIMEOUT"
    )


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    side_effect=lambda name: {
        "npm": "/usr/bin/npm",
        "yarn": "/usr/bin/yarn",
        "pnpm": "/usr/bin/pnpm",
    }[name],
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
    side_effect=[
        _completed("10.9.2\n"),
        _completed("4.9.3\n"),
        _completed("10.6.0\n"),
    ],
)
def test_multiple_managers(
    mock_run,
    mock_which,
):
    request = PackageManagerAvailabilityValidationInput(
        package_managers=("npm", "yarn", "pnpm"),
    )

    result = validate_package_manager_availability(request)

    assert result.valid is True
    assert result.available_count == 3
    assert result.missing_count == 0

    assert [
        item.name
        for item in result.package_managers
    ] == ["npm", "yarn", "pnpm"]


@patch(
    "sentinelshield.package_manager_availability_validation.shutil.which",
    return_value="/usr/bin/npm",
)
@patch(
    "sentinelshield.package_manager_availability_validation.subprocess.run",
    return_value=_completed("10.9.2\n"),
)
def test_aliases_return_same_result(
    mock_run,
    mock_which,
):
    request = PackageManagerAvailabilityValidationInput()

    first = validate_package_manager_availability(request)
    second = package_manager_availability_validation(request)
    third = check_package_manager_availability(request)

    assert first == second == third
    assert are_package_managers_available(request) is True


def test_version_from_stderr_is_accepted():
    with patch(
        "sentinelshield.package_manager_availability_validation.shutil.which",
        return_value="/usr/bin/npm",
    ), patch(
        "sentinelshield.package_manager_availability_validation.subprocess.run",
        return_value=type(
            "Completed",
            (),
            {
                "stdout": "",
                "stderr": "10.9.2",
            },
        )(),
    ):
        result = validate_package_manager_availability()

    assert result.valid is True
    assert result.package_managers[0].version == "10.9.2"
