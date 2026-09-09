from pathlib import Path

from sentinelshield.runtime_version import (
    detect_runtime_version,
    detect_runtime_versions,
)


def test_python_version_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".python-version").write_text("3.12.4\n")

    result = detect_runtime_version(root)

    assert result.found is True
    assert result.runtimes == ("python",)
    assert result.versions[0].runtime == "python"
    assert result.versions[0].version == "3.12.4"
    assert result.versions[0].source == Path(".python-version")


def test_node_version_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".nvmrc").write_text("v22.14.0\n")

    result = detect_runtime_version(root)

    assert result.found is True
    assert result.versions[0].runtime == "node"
    assert result.versions[0].version == "22.14.0"


def test_node_version_alternative_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".node-version").write_text("20.11.1\n")

    result = detect_runtime_version(root)

    assert result.versions[0].version == "20.11.1"


def test_java_version_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".java-version").write_text("21\n")

    result = detect_runtime_version(root)

    assert result.versions[0].runtime == "java"
    assert result.versions[0].version == "21"


def test_ruby_version_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".ruby-version").write_text("3.3.5\n")

    result = detect_runtime_version(root)

    assert result.versions[0].runtime == "ruby"
    assert result.versions[0].version == "3.3.5"


def test_go_version_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".go-version").write_text("1.23.4\n")

    result = detect_runtime_version(root)

    assert result.versions[0].runtime == "go"
    assert result.versions[0].version == "1.23.4"


def test_rust_toolchain_file(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "rust-toolchain").write_text("1.82.0\n")

    result = detect_runtime_version(root)

    assert result.versions[0].runtime == "rust"
    assert result.versions[0].version == "1.82.0"


def test_rust_toolchain_toml(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.81.0"\n'
    )

    result = detect_runtime_version(root)

    assert result.versions[0].runtime == "rust"
    assert result.versions[0].version == "1.81.0"


def test_asdf_tool_versions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".tool-versions").write_text(
        "python 3.12.4\nnodejs 22.14.0\n"
    )

    result = detect_runtime_version(root)

    assert result.found is True
    assert result.versions[0].runtime == "asdf"
    assert result.versions[0].version == "3.12.4"


def test_nested_version_file(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / ".python-version").write_text("3.11.9\n")

    result = detect_runtime_version(root)

    assert result.versions[0].source == Path(
        "services/api/.python-version"
    )


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv"
    ignored.mkdir(parents=True)
    (ignored / ".python-version").write_text("9.9.9\n")

    result = detect_runtime_version(root)

    assert result.found is False
    assert result.versions == ()


def test_symlink_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / ".python-version").write_text("3.12.0\n")
    (root / "linked").symlink_to(target, target_is_directory=True)

    result = detect_runtime_version(root)

    assert result.found is False


def test_empty_version_is_ignored(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".python-version").write_text("\n")

    result = detect_runtime_version(root)

    assert result.found is False


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".node-version").write_text("22\n")
    (root / ".python-version").write_text("3.12\n")
    (root / ".java-version").write_text("21\n")

    result = detect_runtime_version(root)

    assert [v.runtime for v in result.versions] == [
        "java",
        "node",
        "python",
    ]


def test_none():
    assert detect_runtime_versions(None).reason == "PATH_IS_NONE"


def test_empty():
    assert detect_runtime_versions("   ").reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    assert detect_runtime_versions(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    assert (
        detect_runtime_versions("/tmp/a\x00b").reason
        == "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_missing_path(tmp_path):
    result = detect_runtime_versions(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = detect_runtime_versions(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_non_runtime_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("project")

    result = detect_runtime_version(root)

    assert result.found is False
    assert result.runtimes == ()
    assert result.reason == "RUNTIME_VERSIONS_NOT_DETECTED"
