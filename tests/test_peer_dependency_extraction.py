import json
from dataclasses import FrozenInstanceError
from pathlib import Path

from sentinelshield.peer_dependency_extraction import (
    PeerDependency,
    PeerDependencyExtractionResult,
    extract_peer_dependencies,
)


def write_package_json(path: Path, data: object) -> None:
    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )


def test_extracts_peer_dependencies(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "name": "library",
            "peerDependencies": {
                "react": "^18.0.0",
                "react-dom": "^18.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True
    assert result.manifest_path == path.resolve()

    assert result.dependencies == (
        PeerDependency(
            name="react",
            version="^18.0.0",
        ),
        PeerDependency(
            name="react-dom",
            version="^18.0.0",
        ),
    )


def test_dependency_type_and_source_are_correct(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "react": "^18.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.dependencies[0].dependency_type == "peer"
    assert result.dependencies[0].source == "peerDependencies"


def test_scoped_peer_dependency_is_supported(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "@scope/ui": "^2.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        PeerDependency(
            name="@scope/ui",
            version="^2.0.0",
        ),
    )


def test_peer_dependencies_are_sorted_deterministically(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "z-library": "1.0.0",
                "A-library": "2.0.0",
                "m-library": "3.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert [dependency.name for dependency in result.dependencies] == [
        "A-library",
        "m-library",
        "z-library",
    ]


def test_missing_peer_dependencies_is_valid_empty_result(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "name": "library",
            "dependencies": {
                "react": "^18.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "NO_PEER_DEPENDENCIES"
    assert result.extracted is True
    assert result.dependencies == ()


def test_empty_peer_dependencies_is_valid(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {},
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True
    assert result.dependencies == ()


def test_only_peer_dependencies_are_extracted(tmp_path: Path):
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
            "peerDependencies": {
                "react": "^18.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.dependencies == (
        PeerDependency(
            name="react",
            version="^18.0.0",
        ),
    )


def test_peer_dependency_range_is_preserved(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "react": ">=18 <20",
                "typescript": "~5.4.0",
                "some-package": "*",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.dependencies == (
        PeerDependency(
            name="react",
            version=">=18 <20",
        ),
        PeerDependency(
            name="some-package",
            version="*",
        ),
        PeerDependency(
            name="typescript",
            version="~5.4.0",
        ),
    )


def test_none_path():
    result = extract_peer_dependencies(None)

    assert result.manifest_path is None
    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "PATH_IS_NONE"


def test_empty_path():
    result = extract_peer_dependencies("")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False
    assert result.dependencies == ()


def test_whitespace_path():
    result = extract_peer_dependencies("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False


def test_unsupported_path_type():
    result = extract_peer_dependencies(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.extracted is False


def test_null_character_is_rejected():
    result = extract_peer_dependencies(
        "/tmp/project\x00/package.json"
    )

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.extracted is False


def test_missing_file(tmp_path: Path):
    path = tmp_path / "package.json"

    result = extract_peer_dependencies(path)

    assert result.status == "PATH_NOT_FOUND"
    assert result.extracted is False
    assert result.dependencies == ()


def test_directory_is_rejected(tmp_path: Path):
    directory = tmp_path / "package.json"
    directory.mkdir()

    result = extract_peer_dependencies(directory)

    assert result.status == "NOT_A_FILE"
    assert result.extracted is False


def test_non_package_json_manifest_is_rejected(tmp_path: Path):
    path = tmp_path / "requirements.txt"

    path.write_text(
        "requests>=2.0\n",
        encoding="utf-8",
    )

    result = extract_peer_dependencies(path)

    assert result.status == "UNSUPPORTED_MANIFEST"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_json_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    path.write_text(
        '{"peerDependencies": ',
        encoding="utf-8",
    )

    result = extract_peer_dependencies(path)

    assert result.status == "PARSE_ERROR"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_manifest_structure_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    path.write_text(
        "[]",
        encoding="utf-8",
    )

    result = extract_peer_dependencies(path)

    assert result.status == "INVALID_MANIFEST_STRUCTURE"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_peer_dependency_section_is_rejected(
    tmp_path: Path,
):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": [
                "react",
            ],
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "INVALID_PEER_DEPENDENCY_SECTION"
    assert result.extracted is False
    assert result.dependencies == ()


def test_invalid_dependency_name_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "": "^18.0.0",
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "INVALID_DEPENDENCY_NAME"
    assert result.extracted is False


def test_invalid_dependency_version_is_rejected(tmp_path: Path):
    path = tmp_path / "package.json"

    write_package_json(
        path,
        {
            "peerDependencies": {
                "react": 123,
            },
        },
    )

    result = extract_peer_dependencies(path)

    assert result.status == "INVALID_DEPENDENCY_VERSION"
    assert result.extracted is False


def test_manifest_is_not_modified(tmp_path: Path):
    path = tmp_path / "package.json"

    data = {
        "name": "library",
        "peerDependencies": {
            "react": "^18.0.0",
        },
    }

    write_package_json(path, data)
    before = path.read_bytes()

    result = extract_peer_dependencies(path)

    after = path.read_bytes()

    assert result.extracted is True
    assert after == before


def test_result_is_immutable():
    result = PeerDependencyExtractionResult(
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
    dependency = PeerDependency(
        name="react",
        version="^18.0.0",
    )

    try:
        dependency.name = "changed"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("Dependency must be immutable")
