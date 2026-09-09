from pathlib import Path

from sentinelshield.dotnet_ecosystem import detect_dotnet_ecosystem


def test_csproj_high_confidence(tmp_path):
    (tmp_path / "App.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["App.csproj"] == "CSPROJ"


def test_fsproj_high_confidence(tmp_path):
    (tmp_path / "App.fsproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["App.fsproj"] == "FSPROJ"


def test_vbproj_high_confidence(tmp_path):
    (tmp_path / "App.vbproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["App.vbproj"] == "VBPROJ"


def test_solution_high_confidence(tmp_path):
    (tmp_path / "App.sln").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["App.sln"] == "SLN"


def test_slnx_high_confidence(tmp_path):
    (tmp_path / "App.slnx").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["App.slnx"] == "SLNX"


def test_global_json_medium(tmp_path):
    (tmp_path / "global.json").write_text("{}")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types["global.json"] == "GLOBAL_JSON"


def test_directory_build_props_medium(tmp_path):
    (tmp_path / "Directory.Build.props").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"


def test_directory_build_targets_medium(tmp_path):
    (tmp_path / "Directory.Build.targets").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"


def test_packages_config_medium(tmp_path):
    (tmp_path / "packages.config").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"


def test_csharp_source_medium(tmp_path):
    (tmp_path / "Program.cs").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types["Program.cs"] == "SOURCE"


def test_fsharp_source_medium(tmp_path):
    (tmp_path / "Program.fs").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"


def test_vb_source_medium(tmp_path):
    (tmp_path / "Program.vb").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"


def test_nested_project(tmp_path):
    project = tmp_path / "src" / "App"
    project.mkdir(parents=True)
    (project / "App.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.detected
    assert r.markers == ["src/App/App.csproj"]


def test_multiple_markers_deterministic(tmp_path):
    (tmp_path / "Z.csproj").write_text("")
    (tmp_path / "A.sln").write_text("")
    (tmp_path / "global.json").write_text("{}")
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.markers == ["A.sln", "Z.csproj", "global.json"]


def test_bin_ignored(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    (d / "Fake.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected


def test_obj_ignored(tmp_path):
    d = tmp_path / "obj"
    d.mkdir()
    (d / "Fake.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected


def test_node_modules_ignored(tmp_path):
    d = tmp_path / "node_modules"
    d.mkdir()
    (d / "Fake.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected


def test_git_ignored(tmp_path):
    d = tmp_path / ".git"
    d.mkdir()
    (d / "Fake.csproj").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "Fake.csproj").write_text("")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_dotnet_ecosystem(tmp_path)
    assert r.markers == ["real/Fake.csproj"]


def test_non_dotnet_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("")
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_project(tmp_path):
    r = detect_dotnet_ecosystem(tmp_path)
    assert not r.detected
    assert r.reason == "DOTNET_ECOSYSTEM_NOT_DETECTED"


def test_none_path():
    r = detect_dotnet_ecosystem(None)
    assert not r.detected
    assert r.reason == "PATH_IS_NONE"


def test_empty_path():
    r = detect_dotnet_ecosystem("   ")
    assert not r.detected
    assert r.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    r = detect_dotnet_ecosystem(123)
    assert not r.detected
    assert r.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_dotnet_ecosystem(str(tmp_path) + "\x00evil")
    assert not r.detected
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_dotnet_ecosystem(tmp_path / "missing")
    assert not r.detected
    assert r.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("")
    r = detect_dotnet_ecosystem(f)
    assert not r.detected
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
