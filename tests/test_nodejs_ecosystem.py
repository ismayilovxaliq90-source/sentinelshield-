from pathlib import Path

from sentinelshield.nodejs_ecosystem import (
    detect_nodejs_ecosystem,
)


def test_package_json_high_confidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "HIGH"
    assert result.reason == "NODEJS_ECOSYSTEM_DETECTED"
    assert result.markers == (Path("package.json"),)
    assert result.marker_types == ("PACKAGE_JSON",)


def test_package_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package-lock.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "HIGH"


def test_yarn_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "yarn.lock").write_text("")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert "YARN_LOCK" in result.marker_types


def test_pnpm_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pnpm-lock.yaml").write_text("")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert "PNPM_LOCK" in result.marker_types


def test_npm_shrinkwrap(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "npm-shrinkwrap.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True


def test_bun_lock(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "bun.lock").write_text("")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True


def test_nvmrc_medium_confidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".nvmrc").write_text("22")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "MEDIUM"
    assert result.marker_types == ("NVMRC",)


def test_node_version_medium_confidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".node-version").write_text("22")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "MEDIUM"


def test_javascript_source(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "index.js").write_text("console.log('x')")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "MEDIUM"
    assert result.marker_types == ("NODE_SOURCE",)


def test_typescript_source(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.ts").write_text("const x: number = 1")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.confidence == "MEDIUM"


def test_nested_project(tmp_path):
    root = tmp_path / "project"
    nested = root / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is True
    assert result.markers == (
        Path("apps/web/package.json"),
    )


def test_node_modules_ignored(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "package.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is False
    assert result.markers == ()


def test_git_ignored(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".git"
    ignored.mkdir(parents=True)
    (ignored / "package.json").write_text("{}")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is False


def test_symlink_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (target / "package.json").write_text("{}")
    (root / "linked").symlink_to(target, target_is_directory=True)

    result = detect_nodejs_ecosystem(root)

    assert result.detected is False


def test_python_only_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text("")

    result = detect_nodejs_ecosystem(root)

    assert result.detected is False
    assert result.confidence == "NONE"
    assert result.reason == "NODEJS_ECOSYSTEM_NOT_DETECTED"


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = detect_nodejs_ecosystem(root)

    assert result.detected is False
    assert result.markers == ()
    assert result.marker_types == ()


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "z.js").write_text("")
    (root / "package.json").write_text("{}")
    (root / "a.ts").write_text("")

    result = detect_nodejs_ecosystem(root)

    assert result.markers == (
        Path("a.ts"),
        Path("package.json"),
        Path("z.js"),
    )


def test_none():
    result = detect_nodejs_ecosystem(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = detect_nodejs_ecosystem("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = detect_nodejs_ecosystem(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = detect_nodejs_ecosystem("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = detect_nodejs_ecosystem(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = detect_nodejs_ecosystem(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
