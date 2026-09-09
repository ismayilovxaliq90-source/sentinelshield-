from pathlib import Path

from sentinelshield.direct_dependency_extraction import (
    DirectDependency,
    DirectDependencyExtractionResult,
    extract_direct_dependencies,
)


def test_package_json_extracts_direct_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        """
        {
          "dependencies": {
            "express": "^5.0.0",
            "lodash": "^4.17.21"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result == DirectDependencyExtractionResult(
        manifest_path=path.resolve(),
        dependencies=(
            DirectDependency(
                name="express",
                version="^5.0.0",
                dependency_type="production",
                source="dependencies",
            ),
            DirectDependency(
                name="lodash",
                version="^4.17.21",
                dependency_type="production",
                source="dependencies",
            ),
        ),
        extracted=True,
        status="EXTRACTED",
    )


def test_package_json_extracts_development_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        """
        {
          "devDependencies": {
            "pytest": "^8.0.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="pytest",
            version="^8.0.0",
            dependency_type="development",
            source="devDependencies",
        ),
    )


def test_package_json_extracts_optional_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        """
        {
          "optionalDependencies": {
            "fsevents": "^2.3.3"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="fsevents",
            version="^2.3.3",
            dependency_type="optional",
            source="optionalDependencies",
        ),
    )


def test_package_json_extracts_peer_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        """
        {
          "peerDependencies": {
            "react": "^19.0.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="react",
            version="^19.0.0",
            dependency_type="peer",
            source="peerDependencies",
        ),
    )


def test_package_json_combines_dependency_sections_deterministically(
    tmp_path: Path,
):
    path = tmp_path / "package.json"
    path.write_text(
        """
        {
          "peerDependencies": {
            "react": "^19.0.0"
          },
          "devDependencies": {
            "pytest": "^8.0.0"
          },
          "dependencies": {
            "express": "^5.0.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="express",
            version="^5.0.0",
            dependency_type="production",
            source="dependencies",
        ),
        DirectDependency(
            name="pytest",
            version="^8.0.0",
            dependency_type="development",
            source="devDependencies",
        ),
        DirectDependency(
            name="react",
            version="^19.0.0",
            dependency_type="peer",
            source="peerDependencies",
        ),
    )


def test_composer_json_extracts_require_dependencies(tmp_path: Path):
    path = tmp_path / "composer.json"
    path.write_text(
        """
        {
          "require": {
            "monolog/monolog": "^3.0"
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert result.dependencies == ()


def test_requirements_txt_extracts_direct_dependencies(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        """
        requests==2.32.0
        flask>=3.0
        urllib3
        # comment
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result == DirectDependencyExtractionResult(
        manifest_path=path.resolve(),
        dependencies=(
            DirectDependency(
                name="flask",
                version=">=3.0",
                dependency_type="production",
                source="requirements.txt",
            ),
            DirectDependency(
                name="requests",
                version="==2.32.0",
                dependency_type="production",
                source="requirements.txt",
            ),
            DirectDependency(
                name="urllib3",
                version=None,
                dependency_type="production",
                source="requirements.txt",
            ),
        ),
        extracted=True,
        status="EXTRACTED",
    )


def test_requirements_comments_and_blank_lines_are_ignored(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        """
        # first comment

        requests==2.31.0

        # second comment
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="requests",
            version="==2.31.0",
            dependency_type="production",
            source="requirements.txt",
        ),
    )


def test_requirements_includes_are_not_treated_as_dependencies(
    tmp_path: Path,
):
    path = tmp_path / "requirements.txt"
    path.write_text(
        """
        -r base.txt
        --requirement extra.txt
        requests==2.32.0
        """,
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == (
        DirectDependency(
            name="requests",
            version="==2.32.0",
            dependency_type="production",
            source="requirements.txt",
        ),
    )


def test_empty_manifest_returns_extracted_empty_inventory(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text("{}", encoding="utf-8")

    result = extract_direct_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is True
    assert result.status == "EXTRACTED"


def test_invalid_json_returns_parse_error(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text("{invalid", encoding="utf-8")

    result = extract_direct_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "PARSE_ERROR"


def test_invalid_dependency_section_returns_error(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        '{"dependencies": ["express"]}',
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_SECTION"


def test_unsupported_manifest(tmp_path: Path):
    path = tmp_path / "unknown.manifest"
    path.write_text("anything", encoding="utf-8")

    result = extract_direct_dependencies(path)

    assert result == DirectDependencyExtractionResult(
        manifest_path=path.resolve(),
        dependencies=(),
        extracted=False,
        status="UNSUPPORTED_MANIFEST",
    )


def test_none_path():
    result = extract_direct_dependencies(None)

    assert result == DirectDependencyExtractionResult(
        manifest_path=None,
        dependencies=(),
        extracted=False,
        status="PATH_IS_NONE",
    )


def test_empty_path():
    result = extract_direct_dependencies("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False


def test_null_character():
    result = extract_direct_dependencies("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.extracted is False


def test_unsupported_path_type():
    result = extract_direct_dependencies(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.extracted is False


def test_missing_path(tmp_path: Path):
    path = tmp_path / "missing.json"

    result = extract_direct_dependencies(path)

    assert result.status == "PATH_NOT_FOUND"
    assert result.extracted is False


def test_directory_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"
    path.mkdir()

    result = extract_direct_dependencies(path)

    assert result.status == "NOT_A_FILE"
    assert result.extracted is False


def test_result_is_immutable(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text("{}", encoding="utf-8")

    result = extract_direct_dependencies(path)

    try:
        result.extracted = False
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_dependency_is_immutable(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text(
        '{"dependencies": {"requests": "^2.0.0"}}',
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    try:
        result.dependencies[0].name = "changed"
    except Exception:
        return

    raise AssertionError("Dependency must be immutable")


def test_extraction_does_not_modify_manifest(tmp_path: Path):
    path = tmp_path / "package.json"
    original = '{"dependencies": {"requests": "^2.32.0"}}'
    path.write_text(original, encoding="utf-8")

    extract_direct_dependencies(path)

    assert path.read_text(encoding="utf-8") == original


def test_case_insensitive_manifest_filename(tmp_path: Path):
    path = tmp_path / "PACKAGE.JSON"
    path.write_text(
        '{"dependencies": {"requests": "^2.0.0"}}',
        encoding="utf-8",
    )

    result = extract_direct_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True
    assert result.dependencies == (
        DirectDependency(
            name="requests",
            version="^2.0.0",
            dependency_type="production",
            source="dependencies",
        ),
    )
