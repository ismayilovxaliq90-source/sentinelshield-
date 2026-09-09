from sentinelshield.php_ecosystem import detect_php_ecosystem


def test_composer_json_high(tmp_path):
    (tmp_path / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"
    assert r.markers == ["composer.json"]
    assert r.marker_types == ["COMPOSER_JSON"]


def test_composer_lock_high(tmp_path):
    (tmp_path / "composer.lock").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"


def test_phpunit_xml_medium(tmp_path):
    (tmp_path / "phpunit.xml").write_text("<phpunit/>")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_phpunit_dist_medium(tmp_path):
    (tmp_path / "phpunit.xml.dist").write_text("<phpunit/>")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_php_source(tmp_path):
    (tmp_path / "index.php").write_text("<?php echo 'x';")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types == ["PHP_SOURCE"]


def test_php_variants(tmp_path):
    (tmp_path / "legacy.php5").write_text("<?php")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_nested_project(tmp_path):
    p = tmp_path / "apps" / "web"
    p.mkdir(parents=True)
    (p / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"
    assert r.markers == ["apps/web/composer.json"]


def test_multiple_markers_deterministic(tmp_path):
    (tmp_path / "composer.lock").write_text("{}")
    (tmp_path / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert r.markers == ["composer.json", "composer.lock"]
    assert r.marker_types == ["COMPOSER_JSON", "COMPOSER_LOCK"]


def test_vendor_ignored(tmp_path):
    p = tmp_path / "vendor"
    p.mkdir()
    (p / "composer.json").write_text("{}")
    (p / "x.php").write_text("<?php")
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected


def test_node_modules_ignored(tmp_path):
    p = tmp_path / "node_modules"
    p.mkdir()
    (p / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected


def test_git_ignored(tmp_path):
    p = tmp_path / ".git"
    p.mkdir()
    (p / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected


def test_target_ignored(tmp_path):
    p = tmp_path / "target"
    p.mkdir()
    (p / "composer.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "composer.json").write_text("{}")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_php_ecosystem(tmp_path)
    assert r.markers == ["real/composer.json"]


def test_non_php_project(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_project(tmp_path):
    r = detect_php_ecosystem(tmp_path)
    assert not r.detected
    assert r.reason == "PHP_ECOSYSTEM_NOT_DETECTED"


def test_none_path():
    assert detect_php_ecosystem(None).reason == "PATH_IS_NONE"


def test_empty_path():
    assert detect_php_ecosystem("   ").reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    assert detect_php_ecosystem(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_php_ecosystem(str(tmp_path) + "\x00evil")
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_php_ecosystem(tmp_path / "missing")
    assert r.reason == "PATH_NOT_FOUND"


def test_file_path(tmp_path):
    p = tmp_path / "file"
    p.write_text("")
    r = detect_php_ecosystem(p)
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
