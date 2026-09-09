from pathlib import Path

from sentinelshield.ci_cd_discovery import discover_ci_cd


def test_github_actions(tmp_path):
    root = tmp_path / "project"
    workflow = root / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text("name: CI\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert "github-actions" in result.systems


def test_gitlab_ci(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".gitlab-ci.yml").write_text("stages: []\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert result.systems == ("gitlab-ci",)


def test_jenkins(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Jenkinsfile").write_text("pipeline {}\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert result.systems == ("jenkins",)


def test_azure_pipelines(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "azure-pipelines.yml").write_text("trigger: none\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert result.systems == ("azure-pipelines",)


def test_travis(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".travis.yml").write_text("language: python\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert result.systems == ("travis-ci",)


def test_nested_config(tmp_path):
    root = tmp_path / "project"
    nested = root / "service" / "ci"
    nested.mkdir(parents=True)
    (nested / ".gitlab-ci.yml").write_text("stages: []\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert "gitlab-ci" in result.systems


def test_none():
    result = discover_ci_cd(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_ci_cd("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character():
    result = discover_ci_cd("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_unsupported_type():
    result = discover_ci_cd(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_missing_path(tmp_path):
    result = discover_ci_cd(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file"
    file.write_text("x")

    result = discover_ci_cd(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_no_ci_cd(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("test")

    result = discover_ci_cd(root)

    assert result.found is False
    assert result.reason == "CI_CD_CONFIG_NOT_FOUND"


def test_multiple_systems(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / ".gitlab-ci.yml").write_text("stages: []\n")
    (root / "Jenkinsfile").write_text("pipeline {}\n")

    result = discover_ci_cd(root)

    assert result.found is True
    assert result.systems == ("gitlab-ci", "jenkins")


def test_does_not_execute_config(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    marker = root / "Jenkinsfile"
    marker.write_text("THIS MUST NOT EXECUTE")

    result = discover_ci_cd(root)

    assert result.found is True
