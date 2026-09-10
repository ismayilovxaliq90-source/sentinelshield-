from pathlib import Path

import pytest

from sentinelshield.package_installation_validation import (
    INSTALL_COMMANDS,
    PackageInstallationValidationError,
    PackageInstallationRequest,
    PackageSpec,
    build_install_command,
    validate_installation_result,
    _validate_command,
)


def test_supported_install_commands_are_allowlisted():
    for manager, command in INSTALL_COMMANDS.items():
        assert build_install_command(manager) == command


def test_unknown_manager_is_rejected():
    with pytest.raises(PackageInstallationValidationError):
        build_install_command("unknown")


def test_string_command_is_rejected():
    with pytest.raises(PackageInstallationValidationError):
        _validate_command("npm", "npm install")


def test_wrong_command_is_rejected():
    with pytest.raises(PackageInstallationValidationError):
        _validate_command("npm", ("npm", "run", "build"))


def test_shell_metacharacter_is_rejected():
    with pytest.raises(PackageInstallationValidationError):
        _validate_command("npm", ("npm", "install", "foo", "&&", "whoami"))


def test_secret_environment_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()

    with pytest.raises(ValueError):
        PackageInstallationRequest(
            repository_root=root,
            package_manager="npm",
            environment={"NPM_TOKEN": "secret"},
        )


def test_empty_package_name_is_rejected():
    with pytest.raises(ValueError):
        PackageSpec("")


def test_validation_rejects_failed_result():
    from sentinelshield.package_installation_validation import (
        PackageInstallationValidationResult,
    )

    result = PackageInstallationValidationResult(
        success=False,
        package_manager="npm",
        command=("npm", "install"),
        exit_code=1,
        timed_out=False,
        stdout="",
        stderr="failure",
        expected_packages=(),
        missing_packages=(),
        unexpected_packages=(),
        fingerprints=(),
        reason="INSTALLATION_COMMAND_FAILED",
    )

    assert validate_installation_result(result) is False


def test_validation_accepts_successful_result():
    from sentinelshield.package_installation_validation import (
        PackageInstallationValidationResult,
    )

    result = PackageInstallationValidationResult(
        success=True,
        package_manager="npm",
        command=("npm", "install"),
        exit_code=0,
        timed_out=False,
        stdout="ok",
        stderr="",
        expected_packages=(),
        missing_packages=(),
        unexpected_packages=(),
        fingerprints=(),
        reason="INSTALLATION_SUCCESS",
    )

    assert validate_installation_result(result) is True
