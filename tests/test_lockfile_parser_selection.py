from pathlib import Path

from sentinelshield.lockfile_parser_selection import (
    LockfileParserSelectionResult,
    select_lockfile_parser,
)


def test_package_lock_selects_json_npm_parser(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="json",
        lockfile_type="npm",
        supported=True,
        status="SELECTED",
    )


def test_yarn_lock_selects_yarn_parser(tmp_path: Path):
    path = tmp_path / "yarn.lock"
    path.write_text("", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="yarn",
        lockfile_type="yarn",
        supported=True,
        status="SELECTED",
    )


def test_pnpm_lock_selects_yaml_pnpm_parser(tmp_path: Path):
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="yaml",
        lockfile_type="pnpm",
        supported=True,
        status="SELECTED",
    )


def test_poetry_lock_selects_toml_poetry_parser(tmp_path: Path):
    path = tmp_path / "poetry.lock"
    path.write_text("", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="toml",
        lockfile_type="poetry",
        supported=True,
        status="SELECTED",
    )


def test_pipfile_lock_selects_json_pipenv_parser(tmp_path: Path):
    path = tmp_path / "Pipfile.lock"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="json",
        lockfile_type="pipenv",
        supported=True,
        status="SELECTED",
    )


def test_cargo_lock_selects_toml_cargo_parser(tmp_path: Path):
    path = tmp_path / "Cargo.lock"
    path.write_text("", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="toml",
        lockfile_type="cargo",
        supported=True,
        status="SELECTED",
    )


def test_composer_lock_selects_json_composer_parser(tmp_path: Path):
    path = tmp_path / "composer.lock"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="json",
        lockfile_type="composer",
        supported=True,
        status="SELECTED",
    )


def test_go_sum_selects_lines_go_parser(tmp_path: Path):
    path = tmp_path / "go.sum"
    path.write_text("", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser="lines",
        lockfile_type="go",
        supported=True,
        status="SELECTED",
    )


def test_filename_matching_is_case_insensitive(tmp_path: Path):
    path = tmp_path / "PACKAGE-LOCK.JSON"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result.parser == "json"
    assert result.lockfile_type == "npm"
    assert result.supported is True
    assert result.status == "SELECTED"


def test_unsupported_lockfile(tmp_path: Path):
    path = tmp_path / "unknown.lock"
    path.write_text("", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert result == LockfileParserSelectionResult(
        lockfile_path=path.resolve(),
        parser=None,
        lockfile_type=None,
        supported=False,
        status="UNSUPPORTED_LOCKFILE",
    )


def test_none_path():
    result = select_lockfile_parser(None)

    assert result == LockfileParserSelectionResult(
        lockfile_path=None,
        parser=None,
        lockfile_type=None,
        supported=False,
        status="PATH_IS_NONE",
    )


def test_empty_path():
    result = select_lockfile_parser("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.supported is False


def test_null_character():
    result = select_lockfile_parser("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.supported is False


def test_unsupported_path_type():
    result = select_lockfile_parser(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.supported is False


def test_missing_path(tmp_path: Path):
    path = tmp_path / "missing.lock"

    result = select_lockfile_parser(path)

    assert result.status == "PATH_NOT_FOUND"
    assert result.supported is False


def test_directory_is_not_lockfile(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.mkdir()

    result = select_lockfile_parser(path)

    assert result.status == "NOT_A_FILE"
    assert result.supported is False


def test_result_type(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    assert isinstance(result, LockfileParserSelectionResult)


def test_result_is_immutable(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text("{}", encoding="utf-8")

    result = select_lockfile_parser(path)

    try:
        result.supported = False
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_selection_does_not_modify_lockfile(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    original = '{"name": "sentinelshield"}'
    path.write_text(original, encoding="utf-8")

    select_lockfile_parser(path)

    assert path.read_text(encoding="utf-8") == original
