from pathlib import Path

import pytest

from sentinelshield.development_dependency_extraction import (
    DevelopmentDependency,
    DevelopmentDependencyExtractionResult,
    extract_development_dependencies,
)


def test_package_json_extracts_dev_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"

    path.write_text(
        """
        {
          "dependencies": {
            "express": "^5.0.0"
          },
          "devDependencies": {
            "pytest": "^8.0.0",
            "eslint": "^9.0.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_development_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert DevelopmentDependency(
        name="eslint",
        version="^9.0.0",
        source="devDependencies",
    ) in result.dependencies

    assert DevelopmentDependency(
        name="pytest",
        version="^8.0.0",
        source="devDependencies",
    ) in result.dependencies

    assert all(
        dependency.name != "express"
        for dependency in result.dependencies
    )


def test_composer_extracts_require_dev(tmp_path: Path):
    path = tmp_path / "composer.json"

    path.write_text(
        """
        {
          "require": {
            "monolog/monolog": "^3.0"
          },
          "require-dev": {
            "phpunit/phpunit": "^11.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_development_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert DevelopmentDependency(
        name="phpunit/phpunit",
        version="^11.0",
        source="require-dev",
    ) in result.dependencies


def test_pipfile_extracts_dev_packages(tmp_path: Path):
    path = tmp_path / "Pipfile"

    path.write_text(
        """
        [packages]
        requests = "*"

        [dev-packages]
        pytest = ">=8.0"
        black = "*"
        """,
        encoding="utf-8",
    )

    result = extract_development_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert DevelopmentDependency(
        name="pytest",
        version=">=8.0",
        source="Pipfile",
    ) in result.dependencies

    assert DevelopmentDependency(
        name="black",
        version="*",
        source="Pipfile",
    ) in result.dependencies

    assert all(
        dependency.name != "requests"
        for dependency in result.dependencies
    )


def test_requirements_txt_extracts_entries(tmp_path: Path):
    path = tmp_path / "requirements.txt"

    path.write_text(
        """
        pytest>=8.0
        black==24.0
        # comment
        """,
        encoding="utf-8",
    )

    result = extract_development_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert DevelopmentDependency(
        name="pytest",
        version=">=8.0",
        source="requirements.txt",
    ) in result.dependencies


def test_missing_path():
    result = extract_development_dependencies(
        "/tmp/does-not-exist-sentinelshield"
    )

    assert result.extracted is False
    assert result.status == "PATH_NOT_FOUND"


def test_none_path():
    result = extract_development_dependencies(None)

    assert result.extracted is False
    assert result.status == "PATH_IS_NONE"


def test_empty_path():
    result = extract_development_dependencies("   ")

    assert result.extracted is False
    assert result.status == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = extract_development_dependencies("/tmp/project\x00evil")

    assert result.extracted is False
    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"


def test_unsupported_manifest(tmp_path: Path):
    path = tmp_path / "Cargo.toml"
    path.write_text("[dependencies]\n", encoding="utf-8")

    result = extract_development_dependencies(path)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_MANIFEST"


def test_invalid_json(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text("{invalid", encoding="utf-8")

    result = extract_development_dependencies(path)

    assert result.extracted is False
    assert result.status == "PARSE_ERROR"


def test_result_is_immutable():
    result = DevelopmentDependencyExtractionResult(
        manifest_path=None,
        dependencies=(),
        extracted=False,
        status="TEST",
    )

    with pytest.raises(AttributeError):
        result.status = "CHANGED"


def test_no_files_are_modified(tmp_path: Path):
    path = tmp_path / "package.json"

    content = """
    {
      "devDependencies": {
        "pytest": "^8.0.0"
      }
    }
    """

    path.write_text(content, encoding="utf-8")
    before = path.read_bytes()

    extract_development_dependencies(path)

    after = path.read_bytes()

    assert before == after
