from pathlib import Path

from sentinelshield.project_metadata import (
    collect_project_metadata,
)


def test_basic_metadata(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n")

    result = collect_project_metadata(root)

    assert result.found is True
    assert result.project_name == "project"
    assert result.metadata_count == 1
    assert result.metadata_files == (Path("pyproject.toml"),)
    assert result.metadata_types == ("python",)
    assert result.reason == "PROJECT_METADATA_COLLECTED"


def test_multiple_metadata_files(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("")
    (root / "package.json").write_text("{}")
    (root / "Cargo.toml").write_text("")

    result = collect_project_metadata(root)

    assert result.metadata_count == 3
    assert result.metadata_types == ("node", "python", "rust")


def test_metadata_is_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "go.mod").write_text("module example")

    result = collect_project_metadata(root)

    assert result.metadata_files == (Path("go.mod"),)


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pom.xml").write_text("")
    (root / "go.mod").write_text("")
    (root / "package.json").write_text("{}")

    result = collect_project_metadata(root)

    assert result.metadata_files == (
        Path("go.mod"),
        Path("package.json"),
        Path("pom.xml"),
    )


def test_dotnet_metadata(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.csproj").write_text("<Project />")
    (root / "lib.fsproj").write_text("<Project />")

    result = collect_project_metadata(root)

    assert result.metadata_count == 2
    assert result.metadata_types == ("dotnet",)


def test_gradle_metadata(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "build.gradle.kts").write_text("")

    result = collect_project_metadata(root)

    assert result.metadata_types == ("gradle",)


def test_no_metadata(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("demo")

    result = collect_project_metadata(root)

    assert result.found is True
    assert result.metadata_count == 0
    assert result.metadata_files == ()
    assert result.metadata_types == ()


def test_nested_metadata_not_collected(tmp_path):
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("")

    result = collect_project_metadata(root)

    assert result.metadata_count == 0


def test_symlink_metadata_ignored(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target.toml"
    root.mkdir()
    target.write_text("")
    (root / "pyproject.toml").symlink_to(target)

    result = collect_project_metadata(root)

    assert result.metadata_count == 0


def test_none():
    result = collect_project_metadata(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = collect_project_metadata("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = collect_project_metadata(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = collect_project_metadata("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = collect_project_metadata(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = collect_project_metadata(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
