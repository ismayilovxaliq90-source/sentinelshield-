from pathlib import Path
from sentinelshield.java_ecosystem import detect_java_ecosystem


def test_pom_xml(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"
    assert r.marker_types == ["POM_XML"]


def test_gradle(tmp_path):
    (tmp_path / "build.gradle").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected and r.confidence == "HIGH"


def test_gradle_kts(tmp_path):
    (tmp_path / "build.gradle.kts").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_settings_gradle(tmp_path):
    (tmp_path / "settings.gradle").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected


def test_settings_gradle_kts(tmp_path):
    (tmp_path / "settings.gradle.kts").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected


def test_maven_wrapper(tmp_path):
    (tmp_path / "mvnw").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected and "MAVEN_WRAPPER" in r.marker_types


def test_gradle_wrapper(tmp_path):
    (tmp_path / "gradlew").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected and "GRADLE_WRAPPER" in r.marker_types


def test_java_source_medium(tmp_path):
    (tmp_path / "Main.java").write_text("class Main {}")
    r = detect_java_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types == ["JAVA_SOURCE"]


def test_nested_java_project(tmp_path):
    p = tmp_path / "app"
    p.mkdir()
    (p / "pom.xml").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.confidence == "HIGH"
    assert r.markers == ["app/pom.xml"]


def test_ignored_target(tmp_path):
    p = tmp_path / "target"
    p.mkdir()
    (p / "pom.xml").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert not r.detected


def test_ignored_node_modules(tmp_path):
    p = tmp_path / "node_modules"
    p.mkdir()
    (p / "pom.xml").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "pom.xml").write_text("")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_java_ecosystem(tmp_path)
    assert r.markers == ["real/pom.xml"]


def test_deterministic_order(tmp_path):
    (tmp_path / "z").mkdir()
    (tmp_path / "a").mkdir()
    (tmp_path / "z" / "pom.xml").write_text("")
    (tmp_path / "a" / "build.gradle").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert r.markers == ["a/build.gradle", "z/pom.xml"]


def test_non_java_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("")
    r = detect_java_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_path():
    r = detect_java_ecosystem("   ")
    assert r.reason == "PATH_IS_EMPTY"


def test_none_path():
    r = detect_java_ecosystem(None)
    assert r.reason == "PATH_IS_NONE"


def test_unsupported_type():
    r = detect_java_ecosystem(123)
    assert r.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_java_ecosystem(str(tmp_path) + "\x00evil")
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_java_ecosystem(tmp_path / "missing")
    assert r.reason == "PATH_NOT_FOUND"


def test_file_path(tmp_path):
    p = tmp_path / "file"
    p.write_text("")
    r = detect_java_ecosystem(p)
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
