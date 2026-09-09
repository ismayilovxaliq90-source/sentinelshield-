from pathlib import Path

from sentinelshield.settings_gradle_discovery import (
    SettingsGradleDiscoveryResult,
    SettingsGradleDiscoverer,
    discover_settings_gradle,
)


def test_settings_gradle_is_discovered(tmp_path):
    settings_file = tmp_path / "settings.gradle"

    settings_file.write_text(
        "rootProject.name = 'example'\n",
        encoding="utf-8",
    )

    result = discover_settings_gradle(tmp_path)

    assert isinstance(
        result,
        SettingsGradleDiscoveryResult,
    )
    assert result.found is True
    assert result.path == settings_file
    assert result.kind == "SETTINGS_GRADLE"
    assert result.reason == "SETTINGS_GRADLE_FOUND"


def test_settings_gradle_kts_is_discovered(tmp_path):
    settings_file = tmp_path / "settings.gradle.kts"

    settings_file.write_text(
        'rootProject.name = "example"\n',
        encoding="utf-8",
    )

    result = discover_settings_gradle(tmp_path)

    assert result.found is True
    assert result.path == settings_file
    assert result.kind == "SETTINGS_GRADLE_KTS"
    assert result.reason == "SETTINGS_GRADLE_FOUND"


def test_settings_gradle_is_preferred_when_both_exist(tmp_path):
    groovy = tmp_path / "settings.gradle"
    kotlin = tmp_path / "settings.gradle.kts"

    groovy.write_text(
        "rootProject.name = 'example'\n",
        encoding="utf-8",
    )
    kotlin.write_text(
        'rootProject.name = "example"\n',
        encoding="utf-8",
    )

    result = discover_settings_gradle(tmp_path)

    assert result.found is True
    assert result.path == groovy
    assert result.kind == "SETTINGS_GRADLE"


def test_missing_settings_gradle_is_reported(tmp_path):
    result = discover_settings_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.kind == "NONE"
    assert result.reason == "SETTINGS_GRADLE_NOT_FOUND"


def test_none_project_path_is_rejected():
    result = discover_settings_gradle(None)

    assert result.found is False
    assert result.path is None
    assert result.kind == "NONE"
    assert result.reason == "PROJECT_PATH_IS_NONE"


def test_empty_project_path_is_rejected():
    result = discover_settings_gradle("")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_whitespace_project_path_is_rejected():
    result = discover_settings_gradle("   ")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_string_project_path_is_supported(tmp_path):
    settings_file = tmp_path / "settings.gradle"

    settings_file.write_text(
        "rootProject.name = 'example'\n",
        encoding="utf-8",
    )

    result = discover_settings_gradle(
        f"  {tmp_path}  "
    )

    assert result.found is True
    assert result.path == settings_file


def test_path_object_is_supported(tmp_path):
    settings_file = tmp_path / "settings.gradle"
    settings_file.touch()

    result = discover_settings_gradle(
        Path(tmp_path)
    )

    assert result.found is True
    assert result.path == settings_file


def test_nonexistent_project_path_is_rejected(tmp_path):
    missing = tmp_path / "missing-project"

    result = discover_settings_gradle(missing)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_DOES_NOT_EXIST"


def test_file_as_project_path_is_rejected(tmp_path):
    project_file = tmp_path / "project.txt"

    project_file.write_text(
        "not a directory",
        encoding="utf-8",
    )

    result = discover_settings_gradle(project_file)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_NOT_DIRECTORY"


def test_unrelated_gradle_files_are_not_selected(tmp_path):
    (tmp_path / "build.gradle").touch()
    (tmp_path / "gradle.properties").touch()

    result = discover_settings_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "SETTINGS_GRADLE_NOT_FOUND"


def test_nested_settings_gradle_is_not_selected(tmp_path):
    nested = tmp_path / "module"
    nested.mkdir()

    nested_settings = nested / "settings.gradle"
    nested_settings.touch()

    result = discover_settings_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "SETTINGS_GRADLE_NOT_FOUND"


def test_discovery_is_read_only(tmp_path):
    settings_file = tmp_path / "settings.gradle"
    settings_file.write_text(
        "rootProject.name = 'example'\n",
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_settings_gradle(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is True
    assert before == after


def test_discovery_does_not_execute_settings_file(tmp_path):
    settings_file = tmp_path / "settings.gradle"

    settings_file.write_text(
        """
        throw new RuntimeException("MUST NOT EXECUTE")
        """,
        encoding="utf-8",
    )

    result = discover_settings_gradle(tmp_path)

    assert result.found is True
    assert result.path == settings_file


def test_integer_project_path_is_rejected():
    result = discover_settings_gradle(123)

    assert result.found is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PROJECT_PATH_TYPE"


def test_list_project_path_is_rejected():
    result = discover_settings_gradle(["/tmp/project"])

    assert result.found is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PROJECT_PATH_TYPE"


def test_directory_named_settings_gradle_is_not_selected(tmp_path):
    settings_directory = tmp_path / "settings.gradle"
    settings_directory.mkdir()

    result = discover_settings_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "SETTINGS_GRADLE_NOT_FOUND"
