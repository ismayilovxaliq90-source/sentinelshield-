from pathlib import Path

from sentinelshield.build_gradle_discovery import (
    BuildGradleDiscoveryResult,
    BuildGradleDiscoverer,
    discover_build_gradle,
)


def test_build_gradle_is_discovered(tmp_path):
    build_file = tmp_path / "build.gradle"
    build_file.write_text(
        "plugins { id 'java' }\n",
        encoding="utf-8",
    )

    result = discover_build_gradle(tmp_path)

    assert isinstance(
        result,
        BuildGradleDiscoveryResult,
    )
    assert result.found is True
    assert result.path == build_file
    assert result.kind == "BUILD_GRADLE"
    assert result.reason == "BUILD_GRADLE_FOUND"


def test_build_gradle_kts_is_discovered(tmp_path):
    build_file = tmp_path / "build.gradle.kts"
    build_file.write_text(
        "plugins { java }\n",
        encoding="utf-8",
    )

    result = discover_build_gradle(tmp_path)

    assert result.found is True
    assert result.path == build_file
    assert result.kind == "BUILD_GRADLE_KTS"
    assert result.reason == "BUILD_GRADLE_FOUND"


def test_build_gradle_is_preferred_when_both_exist(tmp_path):
    groovy = tmp_path / "build.gradle"
    kotlin = tmp_path / "build.gradle.kts"

    groovy.write_text(
        "plugins { id 'java' }\n",
        encoding="utf-8",
    )
    kotlin.write_text(
        "plugins { java }\n",
        encoding="utf-8",
    )

    result = discover_build_gradle(tmp_path)

    assert result.found is True
    assert result.path == groovy
    assert result.kind == "BUILD_GRADLE"


def test_missing_build_gradle_is_reported(tmp_path):
    result = discover_build_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.kind == "NONE"
    assert result.reason == "BUILD_GRADLE_NOT_FOUND"


def test_none_project_path_is_rejected():
    result = discover_build_gradle(None)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_NONE"


def test_empty_project_path_is_rejected():
    result = discover_build_gradle("")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_whitespace_project_path_is_rejected():
    result = discover_build_gradle("   ")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_project_path_string_is_supported(tmp_path):
    build_file = tmp_path / "build.gradle"
    build_file.write_text(
        "// Gradle build file\n",
        encoding="utf-8",
    )

    result = discover_build_gradle(
        f"  {tmp_path}  "
    )

    assert result.found is True
    assert result.path == build_file


def test_path_object_is_supported(tmp_path):
    build_file = tmp_path / "build.gradle"
    build_file.touch()

    result = discover_build_gradle(
        Path(tmp_path)
    )

    assert result.found is True
    assert result.path == build_file


def test_non_directory_project_path_is_rejected(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text(
        "not a directory",
        encoding="utf-8",
    )

    result = discover_build_gradle(file_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_IS_NOT_DIRECTORY"


def test_nonexistent_project_path_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = discover_build_gradle(missing)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_PATH_DOES_NOT_EXIST"


def test_unrelated_gradle_files_are_not_selected(tmp_path):
    (tmp_path / "settings.gradle").touch()
    (tmp_path / "gradle.properties").touch()

    result = discover_build_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "BUILD_GRADLE_NOT_FOUND"


def test_discovery_is_read_only(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_build_gradle(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is False
    assert before == after


def test_discovery_does_not_execute_build_file(tmp_path):
    build_file = tmp_path / "build.gradle"

    # If this file were executed, the marker would be created.
    build_file.write_text(
        """
        // Discovery must never evaluate this file.
        throw new RuntimeException("MUST NOT EXECUTE")
        """,
        encoding="utf-8",
    )

    marker = tmp_path / "execution-marker"

    assert not marker.exists()

    result = discover_build_gradle(tmp_path)

    assert result.found is True
    assert result.path == build_file
    assert not marker.exists()


def test_nested_build_gradle_is_not_selected(tmp_path):
    nested = tmp_path / "module"
    nested.mkdir()

    nested_build = nested / "build.gradle"
    nested_build.touch()

    result = discover_build_gradle(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "BUILD_GRADLE_NOT_FOUND"


def test_integer_project_path_is_rejected():
    result = discover_build_gradle(123)

    assert result.found is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PROJECT_PATH_TYPE"
