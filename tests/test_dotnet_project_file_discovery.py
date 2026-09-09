from pathlib import Path

from sentinelshield.dotnet_project_file_discovery import (
    DotNetProjectFileDiscoveryResult,
    discover_dotnet_project_files,
)


def test_finds_csproj(tmp_path: Path):
    project = tmp_path / "App.csproj"
    project.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.found is True
    assert result.repository_root == tmp_path.resolve()
    assert result.files == (project.resolve(),)


def test_finds_fsproj(tmp_path: Path):
    project = tmp_path / "Library.fsproj"
    project.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.files == (project.resolve(),)


def test_finds_vbproj(tmp_path: Path):
    project = tmp_path / "Legacy.vbproj"
    project.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.files == (project.resolve(),)


def test_finds_nested_projects(tmp_path: Path):
    first = tmp_path / "src" / "Api" / "Api.csproj"
    second = tmp_path / "src" / "Core" / "Core.fsproj"

    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)

    first.write_text("<Project />", encoding="utf-8")
    second.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.files == tuple(
        sorted(
            (first.resolve(), second.resolve()),
            key=str,
        )
    )


def test_case_insensitive_extension(tmp_path: Path):
    project = tmp_path / "App.CSPROJ"
    project.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.files == (project.resolve(),)


def test_ignores_non_dotnet_files(tmp_path: Path):
    for name in (
        "package.json",
        "pom.xml",
        "build.gradle",
        "Cargo.toml",
        "App.cs",
        "README.md",
    ):
        (tmp_path / name).write_text("x", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.files == ()


def test_empty_repository(tmp_path: Path):
    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.files == ()


def test_none():
    result = discover_dotnet_project_files(None)

    assert result.status == "PATH_IS_NONE"
    assert result.files == ()


def test_empty_path():
    result = discover_dotnet_project_files("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.files == ()


def test_null_character():
    result = discover_dotnet_project_files("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.files == ()


def test_unsupported_type():
    result = discover_dotnet_project_files(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.files == ()


def test_non_directory(tmp_path: Path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")

    result = discover_dotnet_project_files(file_path)

    assert result.status == "NOT_A_DIRECTORY"
    assert result.files == ()


def test_whitespace_normalization(tmp_path: Path):
    project = tmp_path / "App.csproj"
    project.write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(f"  {tmp_path}  ")

    assert result.status == "FOUND"
    assert result.repository_root == tmp_path.resolve()
    assert result.files == (project.resolve(),)
def test_symlink_project_is_ignored(tmp_path: Path):
    real = tmp_path / "Real.csproj"
    real.write_text("<Project />", encoding="utf-8")

    link = tmp_path / "Linked.csproj"

    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        return

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.found is True
    assert result.files == (real.resolve(),)
def test_symlink_directory_is_not_traversed(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}_outside"

    try:
        outside.mkdir()

        project = outside / "Outside.csproj"
        project.write_text("<Project />", encoding="utf-8")

        link = tmp_path / "linked"

        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            return

        result = discover_dotnet_project_files(tmp_path)

        assert result.status == "NOT_FOUND"
        assert result.files == ()

    finally:
        if outside.exists():
            for child in outside.iterdir():
                child.unlink(missing_ok=True)

            try:
                outside.rmdir()
            except OSError:
                pass


def test_result_type(tmp_path: Path):
    result = discover_dotnet_project_files(tmp_path)

    assert isinstance(result, DotNetProjectFileDiscoveryResult)


def test_result_is_immutable(tmp_path: Path):
    result = discover_dotnet_project_files(tmp_path)

    try:
        result.found = True
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_deterministic_order(tmp_path: Path):
    for name in (
        "Z.csproj",
        "A.fsproj",
        "M.vbproj",
    ):
        (tmp_path / name).write_text("<Project />", encoding="utf-8")

    result = discover_dotnet_project_files(tmp_path)

    assert result.files == tuple(
        sorted(result.files, key=str)
    )


def test_project_file_is_not_executed(tmp_path: Path):
    project = tmp_path / "Danger.csproj"

    project.write_text(
        '<Project><Target Name="Build">'
        '<Exec Command="touch SHOULD_NOT_EXIST" />'
        "</Target></Project>",
        encoding="utf-8",
    )

    result = discover_dotnet_project_files(tmp_path)

    assert result.status == "FOUND"
    assert result.files == (project.resolve(),)
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
