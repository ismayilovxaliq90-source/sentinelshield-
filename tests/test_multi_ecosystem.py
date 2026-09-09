from pathlib import Path

from sentinelshield.multi_ecosystem import detect_multi_ecosystem


def test_python_only():
    root = Path(__file__).parent / "tmp_multi_python"
    root.mkdir(exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\n")
    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is True
        assert result.ecosystems == ["Python"]
        assert result.ecosystem_count == 1
        assert result.confidence == "HIGH"
        assert result.reason == "SINGLE_ECOSYSTEM_DETECTED"
    finally:
        (root / "pyproject.toml").unlink()
        root.rmdir()


def test_python_node_multi():
    root = Path(__file__).parent / "tmp_multi_python_node"
    root.mkdir(exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\n")
    (root / "package.json").write_text("{}")
    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is True
        assert result.ecosystems == ["Node.js", "Python"]
        assert result.ecosystem_count == 2
        assert result.reason == "MULTIPLE_ECOSYSTEMS_DETECTED"
    finally:
        (root / "pyproject.toml").unlink()
        (root / "package.json").unlink()
        root.rmdir()


def test_java_rust_dotnet_multi():
    root = Path(__file__).parent / "tmp_multi_java_rust_dotnet"
    root.mkdir(exist_ok=True)
    (root / "pom.xml").write_text("<project/>")
    (root / "Cargo.toml").write_text("[package]\n")
    (root / "App.csproj").write_text("<Project/>")
    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is True
        assert result.ecosystems == [".NET", "Java", "Rust"]
        assert result.ecosystem_count == 3
    finally:
        (root / "pom.xml").unlink()
        (root / "Cargo.toml").unlink()
        (root / "App.csproj").unlink()
        root.rmdir()


def test_all_ecosystems():
    root = Path(__file__).parent / "tmp_multi_all"
    root.mkdir(exist_ok=True)

    files = {
        "pyproject.toml": "[project]\n",
        "package.json": "{}",
        "pom.xml": "<project/>",
        "go.mod": "module example\n",
        "Cargo.toml": "[package]\n",
        "composer.json": "{}",
        "Gemfile": "source 'https://rubygems.org'\n",
        "App.csproj": "<Project/>",
        "CMakeLists.txt": "cmake_minimum_required(VERSION 3.10)\n",
    }

    for name, content in files.items():
        (root / name).write_text(content)

    try:
        result = detect_multi_ecosystem(root)

        assert result.detected is True
        assert result.ecosystem_count == 9
        assert result.ecosystems == [
            ".NET",
            "C/C++",
            "Go",
            "Java",
            "Node.js",
            "PHP",
            "Python",
            "Ruby",
            "Rust",
        ]
        assert result.confidence == "HIGH"
        assert result.reason == "MULTIPLE_ECOSYSTEMS_DETECTED"
    finally:
        for name in files:
            (root / name).unlink()
        root.rmdir()


def test_nested_ecosystems():
    root = Path(__file__).parent / "tmp_multi_nested"
    nested = root / "frontend"
    nested.mkdir(parents=True, exist_ok=True)

    (root / "go.mod").write_text("module example\n")
    (nested / "package.json").write_text("{}")

    try:
        result = detect_multi_ecosystem(root)
        assert result.ecosystems == ["Go", "Node.js"]
        assert result.ecosystem_count == 2
        assert "frontend/package.json" in result.markers
    finally:
        (root / "go.mod").unlink()
        (nested / "package.json").unlink()
        nested.rmdir()
        root.rmdir()


def test_ignored_directories():
    root = Path(__file__).parent / "tmp_multi_ignored"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True, exist_ok=True)

    (ignored / "package.json").write_text("{}")
    (root / "main.py").write_text("print('x')")

    try:
        result = detect_multi_ecosystem(root)
        assert result.ecosystems == ["Python"]
        assert result.markers == ["main.py"]
    finally:
        (ignored / "package.json").unlink()
        (root / "main.py").unlink()
        ignored.rmdir()
        root.rmdir()


def test_git_ignored():
    root = Path(__file__).parent / "tmp_multi_git"
    git = root / ".git"
    git.mkdir(parents=True, exist_ok=True)

    (git / "package.json").write_text("{}")
    (root / "main.cpp").write_text("int main() {}")

    try:
        result = detect_multi_ecosystem(root)
        assert result.ecosystems == ["C/C++"]
        assert result.markers == ["main.cpp"]
    finally:
        (git / "package.json").unlink()
        (root / "main.cpp").unlink()
        git.rmdir()
        root.rmdir()


def test_bin_obj_ignored():
    root = Path(__file__).parent / "tmp_multi_bin_obj"
    bin_dir = root / "bin"
    obj_dir = root / "obj"

    bin_dir.mkdir(parents=True, exist_ok=True)
    obj_dir.mkdir(parents=True, exist_ok=True)

    (bin_dir / "App.csproj").write_text("<Project/>")
    (obj_dir / "Other.csproj").write_text("<Project/>")
    (root / "Program.cs").write_text("class Program {}")

    try:
        result = detect_multi_ecosystem(root)
        assert result.ecosystems == [".NET"]
        assert result.markers == ["Program.cs"]
    finally:
        (bin_dir / "App.csproj").unlink()
        (obj_dir / "Other.csproj").unlink()
        (root / "Program.cs").unlink()
        bin_dir.rmdir()
        obj_dir.rmdir()
        root.rmdir()


def test_symlink_not_followed():
    root = Path(__file__).parent / "tmp_multi_symlink"
    target = root / "real"
    link = root / "linked"

    target.mkdir(parents=True, exist_ok=True)
    (target / "package.json").write_text("{}")

    try:
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            return

        result = detect_multi_ecosystem(root)

        assert result.ecosystems == ["Node.js"]
        assert result.markers == ["real/package.json"]
    finally:
        if link.exists() or link.is_symlink():
            link.unlink()
        (target / "package.json").unlink()
        target.rmdir()
        root.rmdir()


def test_multiple_markers_are_deterministic():
    root = Path(__file__).parent / "tmp_multi_sorted"
    root.mkdir(exist_ok=True)

    (root / "Z.csproj").write_text("<Project/>")
    (root / "A.csproj").write_text("<Project/>")
    (root / "package.json").write_text("{}")
    (root / "pyproject.toml").write_text("[project]\n")

    try:
        result1 = detect_multi_ecosystem(root)
        result2 = detect_multi_ecosystem(root)

        assert result1.markers == [
            "A.csproj",
            "Z.csproj",
            "package.json",
            "pyproject.toml",
        ]
        assert result1.markers == result2.markers
        assert result1.ecosystems == result2.ecosystems
    finally:
        for name in [
            "Z.csproj",
            "A.csproj",
            "package.json",
            "pyproject.toml",
        ]:
            (root / name).unlink()
        root.rmdir()


def test_source_only_detection():
    root = Path(__file__).parent / "tmp_multi_source"
    root.mkdir(exist_ok=True)

    (root / "main.py").write_text("print('x')")
    (root / "app.js").write_text("console.log('x')")

    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is True
        assert result.ecosystems == ["Node.js", "Python"]
        assert result.ecosystem_count == 2
    finally:
        (root / "main.py").unlink()
        (root / "app.js").unlink()
        root.rmdir()


def test_no_ecosystem():
    root = Path(__file__).parent / "tmp_multi_none"
    root.mkdir(exist_ok=True)

    (root / "README.md").write_text("# test\n")

    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is False
        assert result.ecosystems == []
        assert result.ecosystem_count == 0
        assert result.confidence == "NONE"
        assert result.reason == "MULTI_ECOSYSTEM_NOT_DETECTED"
    finally:
        (root / "README.md").unlink()
        root.rmdir()


def test_empty_project():
    root = Path(__file__).parent / "tmp_multi_empty"
    root.mkdir(exist_ok=True)

    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is False
        assert result.ecosystems == []
        assert result.ecosystem_count == 0
    finally:
        root.rmdir()


def test_none_path():
    result = detect_multi_ecosystem(None)
    assert result.detected is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_path():
    result = detect_multi_ecosystem("")
    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_path():
    result = detect_multi_ecosystem("   ")
    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = detect_multi_ecosystem(123)
    assert result.detected is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = detect_multi_ecosystem("/tmp/project\x00evil")
    assert result.detected is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path():
    result = detect_multi_ecosystem(
        "/tmp/sentinelshield-this-path-does-not-exist"
    )
    assert result.detected is False
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path():
    root = Path(__file__).parent / "tmp_multi_file"
    root.write_text("not a directory")

    try:
        result = detect_multi_ecosystem(root)
        assert result.detected is False
        assert result.reason == "PATH_IS_NOT_DIRECTORY"
    finally:
        root.unlink()
