from sentinelshield.ruby_ecosystem import detect_ruby_ecosystem


def test_gemfile_high(tmp_path):
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"
    assert r.marker_types == ["GEMFILE"]


def test_gemfile_lock_high(tmp_path):
    (tmp_path / "Gemfile.lock").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"


def test_ruby_version_medium(tmp_path):
    (tmp_path / ".ruby-version").write_text("3.3.0")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_ruby_gemset_medium(tmp_path):
    (tmp_path / ".ruby-gemset").write_text("app")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_rakefile_medium(tmp_path):
    (tmp_path / "Rakefile").write_text("task :test")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_ruby_source(tmp_path):
    (tmp_path / "main.rb").write_text("puts 'hello'")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types == ["RUBY_SOURCE"]


def test_rake_source(tmp_path):
    (tmp_path / "tasks.rake").write_text("task :build")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_gemspec_source(tmp_path):
    (tmp_path / "app.gemspec").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.detected and r.confidence == "MEDIUM"


def test_nested_project(tmp_path):
    p = tmp_path / "apps" / "web"
    p.mkdir(parents=True)
    (p / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.confidence == "HIGH"
    assert r.markers == ["apps/web/Gemfile"]


def test_multiple_markers_sorted(tmp_path):
    (tmp_path / "Gemfile.lock").write_text("")
    (tmp_path / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert r.markers == ["Gemfile", "Gemfile.lock"]
    assert r.marker_types == ["GEMFILE", "GEMFILE_LOCK"]


def test_vendor_ignored(tmp_path):
    p = tmp_path / "vendor"
    p.mkdir()
    (p / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected


def test_bundle_ignored(tmp_path):
    p = tmp_path / ".bundle"
    p.mkdir()
    (p / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected


def test_node_modules_ignored(tmp_path):
    p = tmp_path / "node_modules"
    p.mkdir()
    (p / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected


def test_git_ignored(tmp_path):
    p = tmp_path / ".git"
    p.mkdir()
    (p / "Gemfile").write_text("")
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "Gemfile").write_text("")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_ruby_ecosystem(tmp_path)
    assert r.markers == ["real/Gemfile"]


def test_non_ruby_project(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_project(tmp_path):
    r = detect_ruby_ecosystem(tmp_path)
    assert not r.detected
    assert r.reason == "RUBY_ECOSYSTEM_NOT_DETECTED"


def test_none_path():
    assert detect_ruby_ecosystem(None).reason == "PATH_IS_NONE"


def test_empty_path():
    assert detect_ruby_ecosystem("   ").reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    assert detect_ruby_ecosystem(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_ruby_ecosystem(str(tmp_path) + "\x00evil")
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_ruby_ecosystem(tmp_path / "missing")
    assert r.reason == "PATH_NOT_FOUND"


def test_file_path(tmp_path):
    p = tmp_path / "file"
    p.write_text("")
    r = detect_ruby_ecosystem(p)
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
