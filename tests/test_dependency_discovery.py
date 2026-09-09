from pathlib import Path

from sentinelshield.dependency_discovery import (
    RepositoryDiscovery,
    discover_repository,
)


def test_discovers_git_repository_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "src" / "app"

    nested.mkdir(parents=True)
    (root / ".git").mkdir()

    result = RepositoryDiscovery().discover(nested)

    assert result.status == "FOUND"
    assert result.root_path == root
    assert ".git" in result.markers
    assert result.reason == "REPOSITORY_ROOT_DISCOVERED"


def test_discovers_project_with_two_markers(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "src"

    nested.mkdir(parents=True)

    (root / "pyproject.toml").write_text("", encoding="utf-8")
    (root / "requirements.txt").write_text("", encoding="utf-8")

    result = discover_repository(nested)

    assert result.status == "FOUND"
    assert result.root_path == root
    assert "pyproject.toml" in result.markers
    assert "requirements.txt" in result.markers


def test_markers_are_sorted(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "src"

    nested.mkdir(parents=True)

    (root / "requirements.txt").write_text("", encoding="utf-8")
    (root / "package.json").write_text("", encoding="utf-8")

    result = RepositoryDiscovery().discover(nested)

    assert result.status == "FOUND"
    assert result.root_path == root
    assert result.markers == tuple(sorted(result.markers))


def test_file_input_uses_parent_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    (root / ".git").mkdir()

    source = root / "example.py"
    source.write_text("print('not executed')", encoding="utf-8")

    result = RepositoryDiscovery().discover(source)

    assert result.status == "FOUND"
    assert result.root_path == root


def test_nonexistent_path_returns_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    result = RepositoryDiscovery().discover(missing)

    assert result.status == "NOT_FOUND"
    assert result.root_path is None
    assert result.reason == "START_PATH_DOES_NOT_EXIST"


def test_no_marker_returns_not_found(tmp_path: Path) -> None:
    plain = tmp_path / "plain"

    plain.mkdir()

    result = RepositoryDiscovery().discover(plain)

    assert result.status == "NOT_FOUND"
    assert result.root_path is None
    assert result.markers == ()


def test_discovery_is_read_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "nested"

    nested.mkdir(parents=True)
    (root / ".git").mkdir()

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = RepositoryDiscovery().discover(nested)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.status == "FOUND"
    assert before == after


def test_project_with_only_one_weak_marker_is_not_found(
    tmp_path: Path,
) -> None:
    root = tmp_path / "single-marker"
    nested = root / "src"

    nested.mkdir(parents=True)

    (root / "package.json").write_text("", encoding="utf-8")

    result = RepositoryDiscovery().discover(nested)

    assert result.status == "NOT_FOUND"
    assert result.root_path is None
