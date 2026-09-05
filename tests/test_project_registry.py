from pathlib import Path

import pytest

from sentinelshield.project_registry import (
    ProjectRecord,
    ProjectRegistry,
)


def test_register_project(tmp_path):
    registry = ProjectRegistry()

    record = registry.register(
        name="demo",
        path=tmp_path,
    )

    assert isinstance(record, ProjectRecord)
    assert record.name == "demo"
    assert Path(record.path) == tmp_path.resolve()
    assert record.enabled is True


def test_register_absolute_path(tmp_path):
    registry = ProjectRegistry()

    record = registry.register(
        name="demo",
        path=str(tmp_path.resolve()),
    )

    assert Path(record.path).is_absolute()


def test_relative_path_rejected(tmp_path):
    registry = ProjectRegistry()

    with pytest.raises(ValueError):
        registry.register(
            name="demo",
            path="relative/project",
        )


def test_missing_path_rejected(tmp_path):
    registry = ProjectRegistry()

    missing = tmp_path / "missing"

    with pytest.raises(FileNotFoundError):
        registry.register(
            name="demo",
            path=missing,
        )


def test_file_path_rejected(tmp_path):
    registry = ProjectRegistry()

    file_path = tmp_path / "project.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        registry.register(
            name="demo",
            path=file_path,
        )


def test_empty_name_rejected(tmp_path):
    registry = ProjectRegistry()

    with pytest.raises(ValueError):
        registry.register(
            name="   ",
            path=tmp_path,
        )


def test_non_string_name_rejected(tmp_path):
    registry = ProjectRegistry()

    with pytest.raises(TypeError):
        registry.register(
            name=123,
            path=tmp_path,
        )


def test_duplicate_project_rejected(tmp_path):
    registry = ProjectRegistry()

    registry.register(
        name="demo",
        path=tmp_path,
    )

    with pytest.raises(ValueError):
        registry.register(
            name="demo",
            path=tmp_path,
        )


def test_get_project(tmp_path):
    registry = ProjectRegistry()

    registry.register(
        name="demo",
        path=tmp_path,
    )

    result = registry.get("demo")

    assert result is not None
    assert result.name == "demo"


def test_unknown_project_returns_none():
    registry = ProjectRegistry()

    assert registry.get("missing") is None


def test_exists(tmp_path):
    registry = ProjectRegistry()

    assert registry.exists("demo") is False

    registry.register(
        name="demo",
        path=tmp_path,
    )

    assert registry.exists("demo") is True


def test_count(tmp_path):
    registry = ProjectRegistry()

    assert registry.count() == 0

    registry.register(
        name="a",
        path=tmp_path,
    )

    assert registry.count() == 1


def test_list_projects_sorted(tmp_path):
    registry = ProjectRegistry()

    a = tmp_path / "a"
    b = tmp_path / "b"

    a.mkdir()
    b.mkdir()

    registry.register(name="z", path=b)
    registry.register(name="a", path=a)

    projects = registry.list_projects()

    assert [p.name for p in projects] == ["a", "z"]


def test_unregister(tmp_path):
    registry = ProjectRegistry()

    registry.register(
        name="demo",
        path=tmp_path,
    )

    registry.unregister("demo")

    assert registry.exists("demo") is False
    assert registry.count() == 0


def test_unregister_missing_rejected():
    registry = ProjectRegistry()

    with pytest.raises(KeyError):
        registry.unregister("missing")


def test_record_is_immutable(tmp_path):
    registry = ProjectRegistry()

    record = registry.register(
        name="demo",
        path=tmp_path,
    )

    with pytest.raises(AttributeError):
        record.name = "changed"


def test_disabled_project(tmp_path):
    registry = ProjectRegistry()

    record = registry.register(
        name="demo",
        path=tmp_path,
        enabled=False,
    )

    assert record.enabled is False


def test_enabled_must_be_bool(tmp_path):
    registry = ProjectRegistry()

    with pytest.raises(TypeError):
        registry.register(
            name="demo",
            path=tmp_path,
            enabled=1,
        )


def test_name_is_trimmed(tmp_path):
    registry = ProjectRegistry()

    record = registry.register(
        name="  demo  ",
        path=tmp_path,
    )

    assert record.name == "demo"
