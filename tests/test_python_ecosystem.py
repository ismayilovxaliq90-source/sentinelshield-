from pathlib import Path

from sentinelshield.python_ecosystem import (
    detect_python_ecosystem,
)


def test_pyproject_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\n")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "HIGH"
    assert result.reason == "PYTHON_ECOSYSTEM_DETECTED"
    assert result.markers == (Path("pyproject.toml"),)
    assert result.marker_types == ("PYPROJECT_TOML",)


def test_requirements_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("requests\n")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "HIGH"


def test_setup_py_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "setup.py").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert "SETUP_PY" in result.marker_types


def test_pipfile_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Pipfile").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert "PIPFILE" in result.marker_types


def test_poetry_lock_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "poetry.lock").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is True


def test_uv_lock_detects_python(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "uv.lock").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is True


def test_python_source_is_medium_confidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("print('x')")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "MEDIUM"
    assert result.marker_types == ("PYTHON_SOURCE",)


def test_nested_python_project(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is True
    assert result.markers == (
        Path("services/api/pyproject.toml"),
    )


def test_ignored_directory_is_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv"
    ignored.mkdir(parents=True)
    (ignored / "fake.py").write_text("")

    result = detect_python_ecosystem(root)

    assert result.detected is False
    assert result.markers == ()


def test_symlink_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / "pyproject.toml").write_text("")

    (root / "linked").symlink_to(target, target_is_directory=True)

    result = detect_python_ecosystem(root)

    assert result.detected is False


def test_non_python_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    result = detect_python_ecosystem(root)

    assert result.detected is False
    assert result.confidence == "NONE"
    assert result.reason == "PYTHON_ECOSYSTEM_NOT_DETECTED"


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "z.py").write_text("")
    (root / "a.py").write_text("")
    (root / "pyproject.toml").write_text("")

    result = detect_python_ecosystem(root)

    assert result.markers == (
        Path("a.py"),
        Path("pyproject.toml"),
        Path("z.py"),
    )


def test_none():
    result = detect_python_ecosystem(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = detect_python_ecosystem("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = detect_python_ecosystem(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = detect_python_ecosystem("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = detect_python_ecosystem(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = detect_python_ecosystem(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
