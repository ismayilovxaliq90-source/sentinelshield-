from pathlib import Path

from sentinelshield.package_manager import detect_package_managers


def test_python_pip_requirements():
    root = Path(__file__).parent / "tmp_pm_pip"
    root.mkdir(exist_ok=True)
    (root / "requirements.txt").write_text("requests==2.0\n")

    try:
        result = detect_package_managers(root)

        assert result.detected is True
        assert result.package_managers == ["pip"]
        assert result.manager_count == 1
        assert result.ecosystems == ["Python"]
        assert result.markers == ["requirements.txt"]
        assert result.marker_types["requirements.txt"] == "Python:pip"
        assert result.confidence == "HIGH"
        assert result.reason == "PACKAGE_MANAGER_DETECTED"
    finally:
        (root / "requirements.txt").unlink()
        root.rmdir()


def test_python_poetry():
    root = Path(__file__).parent / "tmp_pm_poetry"
    root.mkdir(exist_ok=True)
    (root / "poetry.lock").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Poetry"]
        assert result.ecosystems == ["Python"]
        assert result.confidence == "HIGH"
    finally:
        (root / "poetry.lock").unlink()
        root.rmdir()


def test_python_pipenv():
    root = Path(__file__).parent / "tmp_pm_pipenv"
    root.mkdir(exist_ok=True)
    (root / "Pipfile").write_text("[packages]\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Pipenv"]
        assert result.ecosystems == ["Python"]
        assert result.confidence == "HIGH"
    finally:
        (root / "Pipfile").unlink()
        root.rmdir()


def test_python_uv():
    root = Path(__file__).parent / "tmp_pm_uv"
    root.mkdir(exist_ok=True)
    (root / "uv.lock").write_text("version = 1\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["uv"]
        assert result.ecosystems == ["Python"]
        assert result.confidence == "HIGH"
    finally:
        (root / "uv.lock").unlink()
        root.rmdir()


def test_node_npm():
    root = Path(__file__).parent / "tmp_pm_npm"
    root.mkdir(exist_ok=True)
    (root / "package-lock.json").write_text("{}")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["npm"]
        assert result.ecosystems == ["Node.js"]
        assert result.confidence == "HIGH"
    finally:
        (root / "package-lock.json").unlink()
        root.rmdir()


def test_node_yarn():
    root = Path(__file__).parent / "tmp_pm_yarn"
    root.mkdir(exist_ok=True)
    (root / "yarn.lock").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Yarn"]
        assert result.ecosystems == ["Node.js"]
    finally:
        (root / "yarn.lock").unlink()
        root.rmdir()


def test_node_pnpm():
    root = Path(__file__).parent / "tmp_pm_pnpm"
    root.mkdir(exist_ok=True)
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["pnpm"]
        assert result.ecosystems == ["Node.js"]
    finally:
        (root / "pnpm-lock.yaml").unlink()
        root.rmdir()


def test_node_bun():
    root = Path(__file__).parent / "tmp_pm_bun"
    root.mkdir(exist_ok=True)
    (root / "bun.lock").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Bun"]
        assert result.ecosystems == ["Node.js"]
    finally:
        (root / "bun.lock").unlink()
        root.rmdir()


def test_java_maven():
    root = Path(__file__).parent / "tmp_pm_maven"
    root.mkdir(exist_ok=True)
    (root / "pom.xml").write_text("<project/>")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Maven"]
        assert result.ecosystems == ["Java"]
        assert result.confidence == "HIGH"
    finally:
        (root / "pom.xml").unlink()
        root.rmdir()


def test_java_gradle():
    root = Path(__file__).parent / "tmp_pm_gradle"
    root.mkdir(exist_ok=True)
    (root / "build.gradle").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Gradle"]
        assert result.ecosystems == ["Java"]
    finally:
        (root / "build.gradle").unlink()
        root.rmdir()


def test_go_modules():
    root = Path(__file__).parent / "tmp_pm_go"
    root.mkdir(exist_ok=True)
    (root / "go.mod").write_text("module example\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Go Modules"]
        assert result.ecosystems == ["Go"]
        assert result.confidence == "HIGH"
    finally:
        (root / "go.mod").unlink()
        root.rmdir()


def test_rust_cargo():
    root = Path(__file__).parent / "tmp_pm_cargo"
    root.mkdir(exist_ok=True)
    (root / "Cargo.toml").write_text("[package]\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Cargo"]
        assert result.ecosystems == ["Rust"]
        assert result.confidence == "HIGH"
    finally:
        (root / "Cargo.toml").unlink()
        root.rmdir()


def test_php_composer():
    root = Path(__file__).parent / "tmp_pm_composer"
    root.mkdir(exist_ok=True)
    (root / "composer.json").write_text("{}")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Composer"]
        assert result.ecosystems == ["PHP"]
        assert result.confidence == "HIGH"
    finally:
        (root / "composer.json").unlink()
        root.rmdir()


def test_ruby_bundler():
    root = Path(__file__).parent / "tmp_pm_bundler"
    root.mkdir(exist_ok=True)
    (root / "Gemfile").write_text("source 'https://rubygems.org'\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Bundler"]
        assert result.ecosystems == ["Ruby"]
        assert result.confidence == "HIGH"
    finally:
        (root / "Gemfile").unlink()
        root.rmdir()


def test_dotnet_nuget():
    root = Path(__file__).parent / "tmp_pm_nuget"
    root.mkdir(exist_ok=True)
    (root / "App.csproj").write_text("<Project/>")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["NuGet"]
        assert result.ecosystems == [".NET"]
        assert result.confidence == "HIGH"
    finally:
        (root / "App.csproj").unlink()
        root.rmdir()


def test_cpp_conan():
    root = Path(__file__).parent / "tmp_pm_conan"
    root.mkdir(exist_ok=True)
    (root / "conanfile.py").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Conan"]
        assert result.ecosystems == ["C/C++"]
        assert result.confidence == "HIGH"
    finally:
        (root / "conanfile.py").unlink()
        root.rmdir()


def test_cpp_vcpkg():
    root = Path(__file__).parent / "tmp_pm_vcpkg"
    root.mkdir(exist_ok=True)
    (root / "vcpkg.json").write_text("{}")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["vcpkg"]
        assert result.ecosystems == ["C/C++"]
        assert result.confidence == "HIGH"
    finally:
        (root / "vcpkg.json").unlink()
        root.rmdir()


def test_multiple_package_managers():
    root = Path(__file__).parent / "tmp_pm_multiple"
    root.mkdir(exist_ok=True)

    files = {
        "requirements.txt": "",
        "package-lock.json": "{}",
        "Cargo.toml": "[package]\n",
    }

    for name, content in files.items():
        (root / name).write_text(content)

    try:
        result = detect_package_managers(root)

        assert result.detected is True
        assert result.package_managers == ["Cargo", "npm", "pip"]
        assert result.manager_count == 3
        assert result.ecosystems == ["Node.js", "Python", "Rust"]
        assert result.confidence == "MEDIUM"
        assert result.reason == "MULTIPLE_PACKAGE_MANAGERS_DETECTED"
    finally:
        for name in files:
            (root / name).unlink()
        root.rmdir()


def test_nested_detection():
    root = Path(__file__).parent / "tmp_pm_nested"
    nested = root / "backend"
    nested.mkdir(parents=True, exist_ok=True)

    (nested / "go.mod").write_text("module example\n")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["Go Modules"]
        assert result.markers == ["backend/go.mod"]
    finally:
        (nested / "go.mod").unlink()
        nested.rmdir()
        root.rmdir()


def test_ignored_directory():
    root = Path(__file__).parent / "tmp_pm_ignored"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True, exist_ok=True)

    (ignored / "package-lock.json").write_text("{}")
    (root / "requirements.txt").write_text("")

    try:
        result = detect_package_managers(root)

        assert result.package_managers == ["pip"]
        assert result.markers == ["requirements.txt"]
    finally:
        (ignored / "package-lock.json").unlink()
        (root / "requirements.txt").unlink()
        ignored.rmdir()
        root.rmdir()


def test_symlink_not_followed():
    root = Path(__file__).parent / "tmp_pm_symlink"
    real = root / "real"
    linked = root / "linked"

    real.mkdir(parents=True, exist_ok=True)
    (real / "package-lock.json").write_text("{}")

    try:
        try:
            linked.symlink_to(real, target_is_directory=True)
        except OSError:
            return

        result = detect_package_managers(root)

        assert result.package_managers == ["npm"]
        assert result.markers == ["real/package-lock.json"]
    finally:
        if linked.exists() or linked.is_symlink():
            linked.unlink()

        (real / "package-lock.json").unlink()
        real.rmdir()
        root.rmdir()


def test_deterministic_order():
    root = Path(__file__).parent / "tmp_pm_order"
    root.mkdir(exist_ok=True)

    files = {
        "z": "requirements.txt",
        "a": "package-lock.json",
    }

    for directory, filename in files.items():
        folder = root / directory
        folder.mkdir()
        (folder / filename).write_text("{}")

    try:
        result1 = detect_package_managers(root)
        result2 = detect_package_managers(root)

        assert result1.markers == [
            "a/package-lock.json",
            "z/requirements.txt",
        ]
        assert result1.markers == result2.markers
        assert result1.package_managers == result2.package_managers
    finally:
        for directory, filename in files.items():
            folder = root / directory
            (folder / filename).unlink()
            folder.rmdir()

        root.rmdir()


def test_no_package_manager():
    root = Path(__file__).parent / "tmp_pm_none"
    root.mkdir(exist_ok=True)
    (root / "README.md").write_text("# test\n")

    try:
        result = detect_package_managers(root)

        assert result.detected is False
        assert result.package_managers == []
        assert result.manager_count == 0
        assert result.ecosystems == []
        assert result.markers == []
        assert result.confidence == "NONE"
        assert result.reason == "PACKAGE_MANAGER_NOT_DETECTED"
    finally:
        (root / "README.md").unlink()
        root.rmdir()


def test_empty_project():
    root = Path(__file__).parent / "tmp_pm_empty"
    root.mkdir(exist_ok=True)

    try:
        result = detect_package_managers(root)

        assert result.detected is False
        assert result.package_managers == []
        assert result.manager_count == 0
    finally:
        root.rmdir()


def test_none_path():
    result = detect_package_managers(None)

    assert result.detected is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_path():
    result = detect_package_managers("")

    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_path():
    result = detect_package_managers("   ")

    assert result.detected is False
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = detect_package_managers(123)

    assert result.detected is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = detect_package_managers("/tmp/project\x00evil")

    assert result.detected is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path():
    result = detect_package_managers(
        "/tmp/sentinelshield-package-manager-does-not-exist"
    )

    assert result.detected is False
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path():
    root = Path(__file__).parent / "tmp_pm_file"
    root.write_text("not a directory")

    try:
        result = detect_package_managers(root)

        assert result.detected is False
        assert result.reason == "PATH_IS_NOT_DIRECTORY"
    finally:
        root.unlink()


def test_pyproject_only_is_not_overclaimed():
    root = Path(__file__).parent / "tmp_pm_pyproject_only"
    root.mkdir(exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n")

    try:
        result = detect_package_managers(root)

        assert result.detected is True
        assert result.package_managers == ["pip"]
        assert result.ecosystems == ["Python"]
        assert result.confidence == "MEDIUM"
        assert result.reason == "PACKAGE_MANAGER_MARKER_DETECTED"
    finally:
        (root / "pyproject.toml").unlink()
        root.rmdir()
