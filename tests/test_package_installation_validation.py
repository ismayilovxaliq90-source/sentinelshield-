from pathlib import Path

import pytest

from sentinelshield.package_installation_validation import (
    InstalledPackage,
    PackageInstallationRequest,
    PackageInstallationResult,
    PackageInstallationValidationError,
    SUPPORTED_MANAGERS,
    attach_installed_packages,
    build_install_command,
    validate_installation_request,
    validate_installed_package,
    validate_package_installation_result,
)


def make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


def test_supported_managers():
    assert {
        "npm",
        "pnpm",
        "yarn",
        "cargo",
        "go",
        "composer",
        "poetry",
    } <= SUPPORTED_MANAGERS


@pytest.mark.parametrize("manager", sorted(SUPPORTED_MANAGERS))
def test_install_command_is_allowlisted_sequence(manager):
    command = build_install_command(manager)

    assert isinstance(command, tuple)
    assert command[0] == manager
    assert all(isinstance(item, str) for item in command)


def test_unknown_manager_rejected():
    with pytest.raises(PackageInstallationValidationError):
        build_install_command("unknown")


def test_npm_requires_package_json(tmp_path):
    workspace = make_workspace(tmp_path)

    with pytest.raises(PackageInstallationValidationError):
        validate_installation_request(
            PackageInstallationRequest(
                workspace=workspace,
                manager="npm",
            )
        )


def test_repository_root_installation_rejected(tmp_path):
    workspace = make_workspace(tmp_path)
    (workspace / ".git").mkdir()
    (workspace / "package.json").write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(PackageInstallationValidationError):
        validate_installation_request(
            PackageInstallationRequest(
                workspace=workspace,
                manager="npm",
            )
        )


def test_workspace_inside_repository_rejected(tmp_path):
    repository = make_workspace(tmp_path)
    (repository / ".git").mkdir()

    workspace = repository / ".sentinelshield-install"
    workspace.mkdir()

    (workspace / "package.json").write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(PackageInstallationValidationError):
        validate_installation_request(
            PackageInstallationRequest(
                workspace=workspace,
                manager="npm",
            )
        )


def test_timeout_validation(tmp_path):
    workspace = make_workspace(tmp_path)
    (workspace / "package.json").write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(PackageInstallationValidationError):
        validate_installation_request(
            PackageInstallationRequest(
                workspace=workspace,
                manager="npm",
                timeout=0,
            )
        )


def test_invalid_environment_rejected(tmp_path):
    workspace = make_workspace(tmp_path)
    (workspace / "package.json").write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )

    with pytest.raises(PackageInstallationValidationError):
        validate_installation_request(
            PackageInstallationRequest(
                workspace=workspace,
                manager="npm",
                environment={"NODE_OPTIONS": "--require malicious"},
            )
        )


def test_success_result_validation():
    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        stdout="ok",
        stderr="",
        timed_out=False,
        installed_packages=(),
        error=None,
    )

    assert validate_package_installation_result(result) is True


def test_failed_result_validation():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=1,
        stdout="",
        stderr="failed",
        timed_out=False,
        installed_packages=(),
        error="PACKAGE_INSTALLATION_FAILED",
    )

    assert validate_package_installation_result(result) is True


def test_timeout_result_invalid():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=None,
        stdout="",
        stderr="",
        timed_out=True,
        installed_packages=(),
        error="PACKAGE_INSTALLATION_TIMEOUT",
    )

    assert validate_package_installation_result(result) is False


def test_installed_package_validation():
    package = InstalledPackage(
        name="is-number",
        version="7.0.0",
        source="npm",
    )

    assert validate_installed_package(package) is True


def test_invalid_installed_package():
    package = InstalledPackage(
        name="",
        version="7.0.0",
    )

    assert validate_installed_package(package) is False


def test_attach_installed_packages():
    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        stdout="ok",
        stderr="",
        timed_out=False,
        installed_packages=(),
        error=None,
    )

    package = InstalledPackage(
        name="is-number",
        version="7.0.0",
        source="npm",
    )

    updated = attach_installed_packages(result, (package,))

    assert len(updated.installed_packages) == 1
    assert updated.installed_packages[0].name == "is-number"


def test_result_serialization():
    package = InstalledPackage(
        name="is-number",
        version="7.0.0",
        source="npm",
    )

    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        stdout="ok",
        stderr="",
        timed_out=False,
        installed_packages=(package,),
        error=None,
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["manager"] == "npm"
    assert data["command"] == ["npm", "ci"]
    assert data["installed_packages"][0]["name"] == "is-number"
