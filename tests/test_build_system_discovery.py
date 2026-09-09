from sentinelshield.build_system_discovery import (
    BuildSystemDiscoveryResult,
    discover_build_system,
)


def test_makefile_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    marker = root / "Makefile"
    marker.write_text("all:\n", encoding="utf-8")

    result = discover_build_system(root)

    assert isinstance(result, BuildSystemDiscoveryResult)
    assert result.found is True
    assert "make" in result.systems
    assert marker in result.markers
    assert result.reason == "BUILD_SYSTEMS_FOUND"


def test_cmake_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    marker = root / "CMakeLists.txt"
    marker.write_text("cmake_minimum_required(VERSION 3.20)\n")

    result = discover_build_system(root)

    assert result.found is True
    assert "cmake" in result.systems


def test_gradle_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "build.gradle").write_text("plugins {}\n")

    result = discover_build_system(root)

    assert result.found is True
    assert "gradle" in result.systems


def test_maven_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pom.xml").write_text("<project/>")

    result = discover_build_system(root)

    assert result.found is True
    assert "maven" in result.systems


def test_cargo_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Cargo.toml").write_text("[package]\nname='x'\n")

    result = discover_build_system(root)

    assert result.found is True
    assert "cargo" in result.systems


def test_nested_marker_detected(tmp_path):
    root = tmp_path / "project"
    nested = root / "src" / "app"
    nested.mkdir(parents=True)
    marker = nested / "Makefile"
    marker.write_text("all:\n")

    result = discover_build_system(root)

    assert result.found is True
    assert marker in result.markers


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / "Makefile").write_text("all:\n")

    result = discover_build_system(root)

    assert result.found is False
    assert result.markers == ()


def test_no_build_system(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("print('x')\n")

    result = discover_build_system(root)

    assert result.found is False
    assert result.systems == ()
    assert result.reason == "BUILD_SYSTEMS_NOT_FOUND"


def test_none_rejected():
    result = discover_build_system(None)

    assert result.reason == "PATH_IS_NONE"


def test_empty_rejected():
    result = discover_build_system("")

    assert result.reason == "PATH_IS_EMPTY"


def test_null_rejected():
    result = discover_build_system("/tmp/x\x00evil")

    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_unsupported_type_rejected():
    result = discover_build_system(123)

    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_file_rejected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    file = root / "main.py"
    file.write_text("x")

    result = discover_build_system(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_path_object_supported(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Makefile").write_text("all:\n")

    result = discover_build_system(root)

    assert result.found is True


def test_multiple_systems(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Makefile").write_text("all:\n")
    (root / "pom.xml").write_text("<project/>")

    result = discover_build_system(root)

    assert result.found is True
    assert "make" in result.systems
    assert "maven" in result.systems


def test_does_not_modify_filesystem(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Makefile").write_text("all:\n")

    before = sorted(str(p.relative_to(tmp_path))
                    for p in tmp_path.rglob("*"))

    result = discover_build_system(root)

    after = sorted(str(p.relative_to(tmp_path))
                   for p in tmp_path.rglob("*"))

    assert result.found is True
    assert before == after


def test_no_build_code_is_executed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    marker = root / "executed.txt"
    (root / "Makefile").write_text(
        f"all:\n\ttouch {marker}\n"
    )

    result = discover_build_system(root)

    assert result.found is True
    assert not marker.exists()
