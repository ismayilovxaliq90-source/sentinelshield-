from pathlib import Path

import pytest

from sentinelshield.package_installation_validation import (
    InstalledPackage,
    PackageInstallationRequest,
    PackageInstallationResult,
    PackageInstallationValidationError,
    build_installation_command,
    validate_installation_result,
    validate_request,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()

    (root / "package.json").write_text(
        """
{
  "name": "fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "is-number": "7.0.0"
  }
}
""".strip(),
        encoding="utf-8",
    )

    (root / "package-lock.json").write_text(
        """
{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "version": "1.0.0"
    }
  }
}
""".strip(),
        encoding="utf-8",
    )

    return root


def test_npm_install_command_is_allowlisted():
    command = build_installation_command("npm")

    assert command == (
        "npm",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )


def test_unknown_manager_rejected():
    with pytest.raises(PackageInstallationValidationError):
        build_installation_command("unknown")


def test_request_requires_manifest_and_lockfile(tmp_path):
    root = make_repo(tmp_path)

    validated = validate_request(
        PackageInstallationRequest(
            repository_root=root,
            manager="npm",
        )
    )

    assert validated == root.resolve()


def test_missing_lockfile_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / "package-lock.json").unlink()

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
                manager="npm",
            )
        )


def test_missing_manifest_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / "package.json").unlink()

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
                manager="npm",
            )
        )


def test_invalid_timeout_rejected(tmp_path):
    root = make_repo(tmp_path)

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
                manager="npm",
                timeout=0,
            )
        )


def test_result_validation_success():
    package = InstalledPackage(
        name="is-number",
        version="7.0.0",
        path=Path("/tmp/node_modules/is-number"),
    )

    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=(
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ),
        returncode=0,
        installed=(package,),
        expected_dependency_count=1,
        actual_dependency_count=1,
        lockfile_present=True,
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )

    assert validate_installation_result(result) is True


def test_result_validation_rejects_count_mismatch():
    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        installed=(),
        expected_dependency_count=2,
        actual_dependency_count=1,
        lockfile_present=True,
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )

    assert validate_installation_result(result) is False


def test_result_validation_rejects_missing_lockfile():
    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        installed=(),
        expected_dependency_count=0,
        actual_dependency_count=0,
        lockfile_present=False,
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )

    assert validate_installation_result(result) is False


def test_failed_result_can_be_valid():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=1,
        installed=(),
        expected_dependency_count=0,
        actual_dependency_count=0,
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="error",
        timed_out=False,
        error="PACKAGE_INSTALLATION_FAILED",
    )

    assert validate_installation_result(result) is True


def test_timeout_result_is_invalid():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=None,
        installed=(),
        expected_dependency_count=0,
        actual_dependency_count=0,
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="",
        timed_out=True,
        error="PACKAGE_INSTALLATION_TIMEOUT",
    )

    assert validate_installation_result(result) is False


def test_serialization():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=1,
        installed=(),
        expected_dependency_count=0,
        actual_dependency_count=0,
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="failure",
        timed_out=False,
        error="PACKAGE_INSTALLATION_FAILED",
    )

    data = result.to_dict()

    assert data["success"] is False
    assert data["manager"] == "npm"
    assert data["command"] == ["npm", "ci"]
    assert data["error"] == "PACKAGE_INSTALLATION_FAILED"
