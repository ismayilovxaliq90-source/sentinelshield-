from sentinelshield.rust_ecosystem import detect_rust_ecosystem


def test_cargo_toml(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    r = detect_rust_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types == ["CARGO_TOML"]


def test_cargo_lock(tmp_path):
    (tmp_path / "Cargo.lock").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"


def test_rust_toolchain(tmp_path):
    (tmp_path / "rust-toolchain").write_text("stable")
    r = detect_rust_ecosystem(tmp_path)
    assert r.detected
    assert "RUST_TOOLCHAIN" in r.marker_types


def test_rust_toolchain_toml(tmp_path):
    (tmp_path / "rust-toolchain.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert r.detected
    assert "RUST_TOOLCHAIN_TOML" in r.marker_types


def test_rust_source(tmp_path):
    (tmp_path / "main.rs").write_text("fn main() {}")
    r = detect_rust_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types == ["RUST_SOURCE"]


def test_nested_project(tmp_path):
    p = tmp_path / "crates" / "app"
    p.mkdir(parents=True)
    (p / "Cargo.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert r.confidence == "HIGH"
    assert r.markers == ["crates/app/Cargo.toml"]


def test_multiple_markers_sorted(tmp_path):
    (tmp_path / "Cargo.lock").write_text("")
    (tmp_path / "Cargo.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert r.markers == ["Cargo.lock", "Cargo.toml"]
    assert r.marker_types == ["CARGO_LOCK", "CARGO_TOML"]


def test_target_ignored(tmp_path):
    p = tmp_path / "target"
    p.mkdir()
    (p / "Cargo.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert not r.detected


def test_node_modules_ignored(tmp_path):
    p = tmp_path / "node_modules"
    p.mkdir()
    (p / "Cargo.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert not r.detected


def test_git_ignored(tmp_path):
    p = tmp_path / ".git"
    p.mkdir()
    (p / "Cargo.toml").write_text("")
    r = detect_rust_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "Cargo.toml").write_text("")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_rust_ecosystem(tmp_path)
    assert r.markers == ["real/Cargo.toml"]


def test_non_rust_project(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    r = detect_rust_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_project(tmp_path):
    r = detect_rust_ecosystem(tmp_path)
    assert not r.detected
    assert r.reason == "RUST_ECOSYSTEM_NOT_DETECTED"


def test_none_path():
    assert detect_rust_ecosystem(None).reason == "PATH_IS_NONE"


def test_empty_path():
    assert detect_rust_ecosystem("   ").reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    assert detect_rust_ecosystem(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_rust_ecosystem(str(tmp_path) + "\x00evil")
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_rust_ecosystem(tmp_path / "missing")
    assert r.reason == "PATH_NOT_FOUND"


def test_file_path(tmp_path):
    p = tmp_path / "file"
    p.write_text("")
    r = detect_rust_ecosystem(p)
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
