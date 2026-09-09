import json
from dataclasses import FrozenInstanceError
from pathlib import Path

from sentinelshield.optional_dependency_extraction import (
    OptionalDependency,
    OptionalDependencyExtractionResult,
    extract_optional_dependencies,
)


def write_package_json(path: Path, data: object) -> None:
    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )


def test_extracts_optional_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "name": "app",
            "optionalDependencies": {
                "fsevents": "^2.3.3",
                "optional-package": "~1.2.0",
            },
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True
    assert result.manifest_path == path.resolve()

    assert result.dependencies == (
        OptionalDependency(
            name="fsevents",
            version="^2.3.3",
        ),
        OptionalDependency(
            name="optional-package",
            version="~1.2.0",
        ),
    )


def test_optional_dependency_type_and_source_are_correct(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {
                "fsevents": "^2.3.3",
            }
        },
    )

    result = extract_optional_dependencies(path)

    dependency = result.dependencies[0]

    assert dependency.dependency_type == "optional"
    assert dependency.source == "optionalDependencies"


def test_optional_dependencies_are_sorted_deterministically(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {
                "z-package": "1.0.0",
                "A-package": "2.0.0",
                "m-package": "3.0.0",
            }
        },
    )

    result = extract_optional_dependencies(path)

    assert [dependency.name for dependency in result.dependencies] == [
        "A-package",
        "m-package",
        "z-package",
    ]


def test_missing_optional_dependencies_is_valid_empty_result(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "name": "app",
            "dependencies": {
                "express": "^5.0.0",
            },
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "NO_OPTIONAL_DEPENDENCIES"
    assert result.extracted is True
    assert result.dependencies == ()


def test_empty_optional_dependencies_is_valid(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {},
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True
    assert result.dependencies == ()


def test_optional_dependencies_do_not_extract_regular_dependencies(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "dependencies": {
                "express": "^5.0.0",
            },
            "devDependencies": {
                "pytest": "^8.0.0",
            },
            "optionalDependencies": {
                "fsevents": "^2.3.3",
            },
        },
    )

    result = extract_optional_dependencies(path)

    assert result.dependencies == (
        OptionalDependency(
            name="fsevents",
            version="^2.3.3",
        ),
    )


def test_scoped_optional_dependency_is_supported(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {
                "@scope/optional-package": "^1.5.0",
            }
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        OptionalDependency(
            name="@scope/optional-package",
            version="^1.5.0",
        ),
    )


def test_none_path():
    result = extract_optional_dependencies(None)

    assert result.manifest_path is None
    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "PATH_IS_NONE"


def test_empty_path():
    result = extract_optional_dependencies("")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False
    assert result.dependencies == ()


def test_whitespace_path():
    result = extract_optional_dependencies("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False


def test_unsupported_path_type():
    result = extract_optional_dependencies(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.extracted is False


def test_null_character_is_rejected():
    result = extract_optional_dependencies("/tmp/project\x00/package.json")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.extracted is False


def test_missing_file(tmp_path: Path):
    path = tmp_path / "package.json"

    result = extract_optional_dependencies(path)

    assert result.status == "PATH_NOT_FOUND"
    assert result.extracted is False
    assert result.dependencies == ()


def test_directory_is_rejected(tmp_path: Path):
    directory = tmp_path / "package.json"
    directory.mkdir()

    result = extract_optional_dependencies(directory)

    assert result.status == "NOT_A_FILE"
    assert result.extracted is False


def test_non_package_json_manifest_is_rejected(tmp_path: Path):
    path = tmp_path / "requirements.txt"

    path.write_text(
        "requests>=2.0\n",
        encoding="utf-8",
    )

    result = extract_optional_dependencies(path)

    assert result.status == "UNSUPPORTED_MANIFEST"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_json_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    path.write_text(
        '{"optionalDependencies": ',
        encoding="utf-8",
    )

    result = extract_optional_dependencies(path)

    assert result.status == "PARSE_ERROR"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_manifest_structure_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    path.write_text(
        "[]",
        encoding="utf-8",
    )

    result = extract_optional_dependencies(path)

    assert result.status == "INVALID_MANIFEST_STRUCTURE"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_optional_dependency_section_is_rejected(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": [
                "fsevents",
            ],
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "INVALID_OPTIONAL_DEPENDENCY_SECTION"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_dependency_name_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {
                "": "^1.0.0",
            },
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "INVALID_DEPENDENCY_NAME"
    assert result.extracted is False


def test_invalid_dependency_version_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "optionalDependencies": {
                "fsevents": 123,
            },
        },
    )

    result = extract_optional_dependencies(path)

    assert result.status == "INVALID_DEPENDENCY_VERSION"
    assert result.extracted is False


def test_manifest_is_not_modified(tmp_path: Path):
    path = tmp_path / "package.json"

    original = {
        "name": "app",
        "optionalDependencies": {
            "fsevents": "^2.3.3",
        },
    }

    write_package_json(path, original)
    before = path.read_bytes()

    result = extract_optional_dependencies(path)

    after = path.read_bytes()

    assert result.extracted is True
    assert after == before


def test_result_is_immutable():
    result = OptionalDependencyExtractionResult(
        manifest_path=None,
        dependencies=(),
        extracted=False,
        status="TEST",
    )

    try:
        result.status = "CHANGED"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("Result must be immutable")


def test_dependency_is_immutable():
    dependency = OptionalDependency(
        name="fsevents",
        version="^2.3.3",
    )

    try:
        dependency.name = "changed"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("Dependency must be immutable")
