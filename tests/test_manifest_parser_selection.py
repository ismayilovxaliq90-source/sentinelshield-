from pathlib import Path

from sentinelshield.manifest_parser_selection import (
    ManifestParserSelectionResult,
    select_manifest_parser,
)


def test_package_json_selects_json_node_parser(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser="json",
        manifest_type="node",
        supported=True,
        status="SELECTED",
    )


def test_cargo_toml_selects_toml_rust_parser(tmp_path: Path):
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text("", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser="toml",
        manifest_type="rust",
        supported=True,
        status="SELECTED",
    )


def test_composer_json_selects_json_php_parser(tmp_path: Path):
    manifest = tmp_path / "composer.json"
    manifest.write_text("{}", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser="json",
        manifest_type="php",
        supported=True,
        status="SELECTED",
    )


def test_pipfile_selects_toml_python_parser(tmp_path: Path):
    manifest = tmp_path / "Pipfile"
    manifest.write_text("", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser="toml",
        manifest_type="python",
        supported=True,
        status="SELECTED",
    )


def test_pyproject_toml_selects_toml_python_parser(tmp_path: Path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser="toml",
        manifest_type="python",
        supported=True,
        status="SELECTED",
    )


def test_manifest_name_matching_is_case_insensitive(tmp_path: Path):
    manifest = tmp_path / "PACKAGE.JSON"
    manifest.write_text("{}", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result.status == "SELECTED"
    assert result.parser == "json"
    assert result.manifest_type == "node"
    assert result.supported is True


def test_unsupported_manifest(tmp_path: Path):
    manifest = tmp_path / "unknown.manifest"
    manifest.write_text("", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert result == ManifestParserSelectionResult(
        manifest_path=manifest.resolve(),
        parser=None,
        manifest_type=None,
        supported=False,
        status="UNSUPPORTED_MANIFEST",
    )


def test_none_path():
    result = select_manifest_parser(None)

    assert result == ManifestParserSelectionResult(
        manifest_path=None,
        parser=None,
        manifest_type=None,
        supported=False,
        status="PATH_IS_NONE",
    )


def test_empty_path():
    result = select_manifest_parser("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.supported is False


def test_null_character():
    result = select_manifest_parser("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.supported is False


def test_unsupported_path_type():
    result = select_manifest_parser(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.supported is False


def test_missing_path(tmp_path: Path):
    manifest = tmp_path / "missing.json"

    result = select_manifest_parser(manifest)

    assert result.status == "PATH_NOT_FOUND"
    assert result.supported is False


def test_directory_is_not_manifest(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.mkdir()

    result = select_manifest_parser(manifest)

    assert result.status == "NOT_A_FILE"
    assert result.supported is False


def test_result_type(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    result = select_manifest_parser(manifest)

    assert isinstance(result, ManifestParserSelectionResult)


def test_result_is_immutable(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    result = select_manifest_parser(manifest)

    try:
        result.supported = False
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_selection_does_not_modify_manifest(tmp_path: Path):
    manifest = tmp_path / "package.json"
    original = '{"name": "sentinelshield"}'
    manifest.write_text(original, encoding="utf-8")

    select_manifest_parser(manifest)

    assert manifest.read_text(encoding="utf-8") == original
