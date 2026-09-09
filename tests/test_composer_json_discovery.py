from pathlib import Path

import pytest

from sentinelshield.composer_json_discovery import (
    ComposerJsonDiscoveryResult,
    discover_composer_json,
)


def test_root_composer_json_is_discovered(tmp_path):
    composer = tmp_path / "composer.json"

    composer.write_text(
        '{"name": "example/project"}\n',
        encoding="utf-8",
    )

    result = discover_composer_json(tmp_path)

    assert isinstance(
        result,
        ComposerJsonDiscoveryResult,
    )
    assert result.repository_root == tmp_path.resolve()
    assert result.found is True
    assert result.status == "FOUND"
    assert result.files == (
        composer.resolve(),
    )


def test_nested_composer_json_is_discovered(tmp_path):
    root = tmp_path / "project"
    nested = root / "packages" / "library"

    nested.mkdir(parents=True)

    composer = nested / "composer.json"
    composer.write_text(
        '{"name": "example/library"}\n',
        encoding="utf-8",
    )

    result = discover_composer_json(root)

    assert result.repository_root == root.resolve()
    assert result.found is True
    assert result.status == "FOUND"
    assert result.files == (
        composer.resolve(),
    )


def test_multiple_composer_json_files_are_discovered(
    tmp_path,
):
    first = tmp_path / "composer.json"

    second_dir = tmp_path / "packages" / "app"
    second_dir.mkdir(parents=True)

    second = second_dir / "composer.json"

    first.write_text(
        '{"name": "root/project"}\n',
        encoding="utf-8",
    )

    second.write_text(
        '{"name": "app/project"}\n',
        encoding="utf-8",
    )

    result = discover_composer_json(tmp_path)

    expected = tuple(
        sorted(
            (
                first.resolve(),
                second.resolve(),
            ),
            key=lambda path: path.as_posix(),
        )
    )

    assert result.found is True
    assert result.status == "FOUND"
    assert result.files == expected


def test_missing_composer_json_returns_not_found(
    tmp_path,
):
    result = discover_composer_json(tmp_path)

    assert result.repository_root == tmp_path.resolve()
    assert result.found is False
    assert result.status == "NOT_FOUND"
    assert result.files == ()


def test_composer_json_directory_is_not_a_file(
    tmp_path,
):
    (tmp_path / "composer.json").mkdir()

    result = discover_composer_json(tmp_path)

    assert result.found is False
    assert result.status == "NOT_FOUND"
    assert result.files == ()


def test_nested_file_is_not_required_at_root(
    tmp_path,
):
    nested = tmp_path / "module"
    nested.mkdir()

    composer = nested / "composer.json"
    composer.write_text(
        "{}",
        encoding="utf-8",
    )

    result = discover_composer_json(tmp_path)

    assert result.found is True
    assert result.files == (
        composer.resolve(),
    )


def test_similarly_named_files_are_ignored(tmp_path):
    (tmp_path / "composer.json.bak").write_text(
        "{}",
        encoding="utf-8",
    )

    (tmp_path / "Composer.json").write_text(
        "{}",
        encoding="utf-8",
    )

    (tmp_path / "composer-json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = discover_composer_json(tmp_path)

    assert result.found is False
    assert result.status == "NOT_FOUND"
    assert result.files == ()


def test_none_is_rejected():
    with pytest.raises(
        TypeError,
        match="must not be None",
    ):
        discover_composer_json(None)


def test_empty_string_is_rejected():
    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        discover_composer_json("")


def test_whitespace_string_is_rejected():
    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        discover_composer_json("   ")


def test_unsupported_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="must be str or pathlib.Path",
    ):
        discover_composer_json(123)


def test_null_character_is_rejected():
    with pytest.raises(
        ValueError,
        match="NULL",
    ):
        discover_composer_json(
            "/tmp/project\x00evil"
        )


def test_nonexistent_repository_root_is_rejected(
    tmp_path,
):
    missing = tmp_path / "does-not-exist"

    with pytest.raises(
        FileNotFoundError,
        match="does not exist",
    ):
        discover_composer_json(missing)


def test_file_repository_root_is_rejected(
    tmp_path,
):
    project_file = tmp_path / "project.txt"

    project_file.write_text(
        "project",
        encoding="utf-8",
    )

    with pytest.raises(
        NotADirectoryError,
        match="not a directory",
    ):
        discover_composer_json(project_file)


def test_string_repository_root_is_supported(
    tmp_path,
):
    composer = tmp_path / "composer.json"

    composer.write_text(
        "{}",
        encoding="utf-8",
    )

    result = discover_composer_json(
        f"  {tmp_path}  "
    )

    assert result.found is True
    assert result.files == (
        composer.resolve(),
    )


def test_path_object_repository_root_is_supported(
    tmp_path,
):
    composer = tmp_path / "composer.json"
    composer.touch()

    result = discover_composer_json(
        Path(tmp_path)
    )

    assert result.found is True
    assert result.files == (
        composer.resolve(),
    )


def test_directory_symlink_is_not_traversed(
    tmp_path,
):
    root = tmp_path / "project"
    external = tmp_path / "external"

    root.mkdir()
    external.mkdir()

    external_composer = external / "composer.json"
    external_composer.write_text(
        "{}",
        encoding="utf-8",
    )

    linked = root / "linked"

    try:
        linked.symlink_to(
            external,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip(
            "directory symlinks unavailable"
        )

    result = discover_composer_json(root)

    assert result.found is False
    assert result.files == ()


def test_symlinked_composer_json_is_ignored(
    tmp_path,
):
    root = tmp_path / "project"
    external = tmp_path / "external"

    root.mkdir()
    external.mkdir()

    real = external / "composer.json"

    real.write_text(
        "{}",
        encoding="utf-8",
    )

    linked = root / "composer.json"

    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip(
            "file symlinks unavailable"
        )

    result = discover_composer_json(root)

    assert result.found is False
    assert result.files == ()


def test_result_files_are_tuple(tmp_path):
    composer = tmp_path / "composer.json"
    composer.touch()

    result = discover_composer_json(tmp_path)

    assert isinstance(
        result.files,
        tuple,
    )


def test_result_is_immutable(tmp_path):
    result = discover_composer_json(tmp_path)

    with pytest.raises(
        AttributeError,
    ):
        result.found = True


def test_discovery_does_not_modify_filesystem(
    tmp_path,
):
    root = tmp_path / "project"
    root.mkdir()

    composer = root / "composer.json"
    composer.write_text(
        '{"name": "example/project"}\n',
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )

    result = discover_composer_json(root)

    after = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
    )

    assert result.found is True
    assert before == after


def test_composer_json_content_is_not_modified(
    tmp_path,
):
    composer = tmp_path / "composer.json"

    content = (
        '{\n'
        '  "name": "example/project",\n'
        '  "require": {\n'
        '    "php": "^8.2"\n'
        '  }\n'
        '}\n'
    )

    composer.write_text(
        content,
        encoding="utf-8",
    )

    result = discover_composer_json(tmp_path)

    assert result.found is True
    assert composer.read_text(
        encoding="utf-8"
    ) == content
