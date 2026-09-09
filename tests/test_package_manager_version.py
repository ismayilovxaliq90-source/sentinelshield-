import json

from sentinelshield.package_manager_version import (
    detect_package_manager_versions,
)


def test_none_path():
    result = detect_package_manager_versions(None)
    assert result.detected is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_path():
    result = detect_package_manager_versions("")
    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_path():
    result = detect_package_manager_versions("   ")
    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = detect_package_manager_versions(123)
    assert result.detected is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = detect_package_manager_versions("/tmp/test\x00evil")
    assert result.detected is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = detect_package_manager_versions(
        tmp_path / "missing"
    )
    assert result.detected is False
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")

    result = detect_package_manager_versions(file)

    assert result.detected is False
    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_npm_package_manager_field(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.8.2"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["npm"]
    assert result.versions[0].version == "10.8.2"
    assert result.versions[0].source == (
        "package.json:packageManager"
    )


def test_yarn_package_manager_field(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "yarn@1.22.22"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["yarn"]
    assert result.versions[0].version == "1.22.22"


def test_pnpm_package_manager_field(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@9.12.3"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["pnpm"]
    assert result.versions[0].version == "9.12.3"


def test_bun_package_manager_field(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "bun@1.1.38"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["bun"]
    assert result.versions[0].version == "1.1.38"


def test_npm_engine(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"engines": {"npm": ">=10.5.0"}}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["npm"]
    assert result.versions[0].version == "10.5.0"


def test_pnpm_engine(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"engines": {"pnpm": ">=9.0.0"}}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["pnpm"]
    assert result.versions[0].version == "9.0.0"


def test_bun_engine(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"engines": {"bun": ">=1.1.0"}}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["bun"]
    assert result.versions[0].version == "1.1.0"


def test_poetry_version_requirement(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry.requires-plugins]
poetry = ">=2.0.0"
""",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["Poetry"]
    assert result.versions[0].version == "2.0.0"


def test_poetry_project_version_is_not_manager_version(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "demo"
version = "1.0.0"
""",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False


def test_maven_wrapper_version(tmp_path):
    wrapper = tmp_path / ".mvn" / "wrapper"
    wrapper.mkdir(parents=True)

    (wrapper / "maven-wrapper.properties").write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/"
        "org/apache/maven/apache-maven/3.9.9/"
        "apache-maven-3.9.9-bin.zip\n",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["Maven"]
    assert result.versions[0].version == "3.9.9"


def test_maven_wrapper_src_distribution(tmp_path):
    wrapper = tmp_path / ".mvn" / "wrapper"
    wrapper.mkdir(parents=True)

    (wrapper / "maven-wrapper.properties").write_text(
        "distributionUrl=https://repo.maven.apache.org/"
        "maven2/org/apache/maven/apache-maven/3.8.8/"
        "apache-maven-3.8.8-src.zip\n",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["Maven"]
    assert result.versions[0].version == "3.8.8"


def test_gradle_wrapper_version(tmp_path):
    wrapper = tmp_path / "gradle" / "wrapper"
    wrapper.mkdir(parents=True)

    (wrapper / "gradle-wrapper.properties").write_text(
        "distributionUrl=https\\://services.gradle.org/"
        "distributions/gradle-8.10.2-bin.zip\n",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["Gradle"]
    assert result.versions[0].version == "8.10.2"


def test_gradle_wrapper_all_distribution(tmp_path):
    wrapper = tmp_path / "gradle" / "wrapper"
    wrapper.mkdir(parents=True)

    (wrapper / "gradle-wrapper.properties").write_text(
        "distributionUrl=https\\://services.gradle.org/"
        "distributions/gradle-8.9-all.zip\n",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.managers == ["Gradle"]
    assert result.versions[0].version == "8.9"


def test_bundler_version(tmp_path):
    (tmp_path / "Gemfile.lock").write_text(
        """
GEM
  remote: https://rubygems.org/

BUNDLED WITH
   2.5.22
""",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["Bundler"]
    assert result.versions[0].version == "2.5.22"


def test_no_explicit_version(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False
    assert result.versions == []
    assert result.reason == (
        "PACKAGE_MANAGER_VERSION_NOT_DETECTED"
    )


def test_invalid_package_json_is_safe(tmp_path):
    (tmp_path / "package.json").write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False


def test_symlink_file_is_ignored(tmp_path):
    real = tmp_path / "real-package.json"
    real.write_text(
        json.dumps({"packageManager": "npm@10.0.0"}),
        encoding="utf-8",
    )

    link = tmp_path / "package.json"

    try:
        link.symlink_to(real)
    except OSError:
        return

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False


def test_symlink_directory_is_not_traversed(tmp_path):
    external = tmp_path.parent / f"{tmp_path.name}_external"
    external.mkdir()

    (external / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.0.0"}),
        encoding="utf-8",
    )

    link = tmp_path / "linked"

    try:
        link.symlink_to(external, target_is_directory=True)
    except OSError:
        return

    try:
        result = detect_package_manager_versions(tmp_path)

        assert result.detected is False
    finally:
        (external / "package.json").unlink()
        external.rmdir()


def test_ignored_node_modules_is_skipped(tmp_path):
    ignored = tmp_path / "node_modules" / "pkg"
    ignored.mkdir(parents=True)

    (ignored / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.0.0"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False


def test_nested_package_json(tmp_path):
    nested = tmp_path / "frontend" / "app"
    nested.mkdir(parents=True)

    (nested / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@9.5.0"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["pnpm"]
    assert result.versions[0].source == (
        "frontend/app/package.json:packageManager"
    )


def test_multiple_managers(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.8.2"}),
        encoding="utf-8",
    )

    wrapper = tmp_path / ".mvn" / "wrapper"
    wrapper.mkdir(parents=True)

    (wrapper / "maven-wrapper.properties").write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/"
        "org/apache/maven/apache-maven/3.9.9/"
        "apache-maven-3.9.9-bin.zip\n",
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.managers == ["Maven", "npm"]
    assert result.manager_count == 2


def test_deterministic_order(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({
            "packageManager": "yarn@1.22.22",
            "engines": {
                "npm": ">=10.0.0",
                "pnpm": ">=9.0.0",
            },
        }),
        encoding="utf-8",
    )

    result1 = detect_package_manager_versions(tmp_path)
    result2 = detect_package_manager_versions(tmp_path)

    assert result1 == result2
    assert result1.managers == ["npm", "pnpm", "yarn"]


def test_root_is_resolved(tmp_path):
    result = detect_package_manager_versions(
        str(tmp_path) + "/."
    )

    assert result.root == tmp_path.resolve()


def test_version_with_v_prefix(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@v10.8.2"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.versions[0].version == "10.8.2"


def test_prerelease_version(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "npm@10.8.2-beta.1"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is True
    assert result.versions[0].version == "10.8.2-beta.1"


def test_unknown_package_manager_is_ignored(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"packageManager": "unknown@1.2.3"}),
        encoding="utf-8",
    )

    result = detect_package_manager_versions(tmp_path)

    assert result.detected is False
