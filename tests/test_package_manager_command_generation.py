import pytest

from sentinelshield.package_manager_command_generation import (
    PackageManagerCommandGenerationError,
    PackageManagerCommandPolicy,
    generate_package_manager_command,
    require_package_manager_command,
)


@pytest.mark.parametrize(
    ("ecosystem", "manager", "package", "version", "expected"),
    [
        (
            "python",
            "pip",
            "requests",
            "2.32.4",
            ("python3", "-m", "pip", "install", "requests==2.32.4"),
        ),
        (
            "python",
            "poetry",
            "requests",
            "2.32.4",
            ("poetry", "add", "requests@2.32.4"),
        ),
        (
            "python",
            "pipenv",
            "requests",
            "2.32.4",
            ("pipenv", "install", "requests==2.32.4"),
        ),
        (
            "node",
            "npm",
            "lodash",
            "4.17.21",
            ("npm", "install", "lodash@4.17.21"),
        ),
        (
            "node",
            "yarn",
            "lodash",
            "4.17.21",
            ("yarn", "add", "lodash@4.17.21"),
        ),
        (
            "node",
            "pnpm",
            "lodash",
            "4.17.21",
            ("pnpm", "add", "lodash@4.17.21"),
        ),
        (
            "rust",
            "cargo",
            "serde",
            "1.0.219",
            ("cargo", "update", "-p", "serde", "--precise", "1.0.219"),
        ),
        (
            "php",
            "composer",
            "monolog/monolog",
            "3.9.0",
            ("composer", "require", "monolog/monolog:3.9.0"),
        ),
        (
            "ruby",
            "bundle",
            "rails",
            None,
            ("bundle", "update", "rails"),
        ),
        (
            "dotnet",
            "dotnet",
            "Newtonsoft.Json",
            "13.0.3",
            (
                "dotnet",
                "add",
                "package",
                "Newtonsoft.Json",
                "--version",
                "13.0.3",
            ),
        ),
        (
            "java",
            "maven",
            "org.example:example",
            "1.2.3",
            (
                "mvn",
                "versions:use-dep-version",
                "-Dincludes=org.example:example",
                "-DdepVersion=1.2.3",
                "-DforceVersion",
            ),
        ),
    ],
)
def test_supported_manager_generates_expected_vector(
    ecosystem,
    manager,
    package,
    version,
    expected,
):
    result = generate_package_manager_command(
        ecosystem,
        manager,
        package,
        version,
    )

    assert result.command == expected
    assert result.executable == expected[0]
    assert result.arguments == expected[1:]
    assert result.executed is False


def test_command_is_immutable_and_structured():
    result = generate_package_manager_command(
        "python",
        "pip",
        "requests",
        "2.32.4",
    )

    assert isinstance(result.command, tuple)
    assert isinstance(result.arguments, tuple)
    assert result.to_dict()["executed"] is False


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "requests;rm",
        "requests && whoami",
        "requests|cat",
        "requests`id`",
        "requests$(id)",
        "requests\nbad",
        "../requests",
    ],
)
def test_malicious_package_is_rejected(value):
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "python",
            "pip",
            value,
            "1.0.0",
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "1.0.0;rm",
        "1.0.0 && whoami",
        "1.0.0|cat",
        "1.0.0`id`",
        "1.0.0$(id)",
        "1.0.0\nbad",
        "../1.0.0",
    ],
)
def test_malicious_version_is_rejected(value):
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "python",
            "pip",
            "requests",
            value,
        )


@pytest.mark.parametrize(
    ("ecosystem", "manager"),
    [
        ("python", "unknown"),
        ("node", "pip"),
        ("rust", "npm"),
        ("php", "npm"),
    ],
)
def test_unsupported_manager_is_rejected(ecosystem, manager):
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            ecosystem,
            manager,
            "package",
            "1.0.0",
        )


def test_cargo_requires_target_version():
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "rust",
            "cargo",
            "serde",
        )


def test_bundler_rejects_explicit_target_version():
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "ruby",
            "bundle",
            "rails",
            "7.0.0",
        )


def test_maven_requires_group_artifact_identifier():
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "java",
            "maven",
            "example",
            "1.0.0",
        )


def test_invalid_types_are_rejected():
    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "python",
            "pip",
            None,
            "1.0.0",
        )

    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "python",
            "pip",
            "requests",
            123,
        )


def test_policy_can_disable_prereleases():
    policy = PackageManagerCommandPolicy(
        allow_prerelease=False,
    )

    with pytest.raises(PackageManagerCommandGenerationError):
        generate_package_manager_command(
            "python",
            "pip",
            "requests",
            "2.0.0rc1",
            policy=policy,
        )


def test_require_wrapper_returns_same_safe_result():
    result = require_package_manager_command(
        "node",
        "npm",
        "lodash",
        "4.17.21",
    )

    assert result.command == (
        "npm",
        "install",
        "lodash@4.17.21",
    )
    assert result.executed is False


def test_generation_does_not_execute():
    result = generate_package_manager_command(
        "python",
        "pip",
        "requests",
        "2.32.4",
    )

    assert result.executed is False
    assert result.command[0] == "python3"
