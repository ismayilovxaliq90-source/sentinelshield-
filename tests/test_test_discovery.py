from pathlib import Path
import pytest

from sentinelshield.test_discovery import (
    TestDiscoveryInput,
    discover_tests,
)


def test_discovers_tests_directory(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.test_files == ("tests/test_a.py",)
    assert r.count == 1
    assert r.status == "FOUND"


def test_discovers_nested_tests(tmp_path):
    p = tmp_path / "service" / "tests"
    p.mkdir(parents=True)
    (p / "test_api.py").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert "service/tests/test_api.py" in r.test_files


def test_discovers_test_suffix(tmp_path):
    (tmp_path / "module_test.py").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.test_files == ("module_test.py",)


def test_discovers_js_tests(tmp_path):
    (tmp_path / "app.test.js").write_text("")
    (tmp_path / "app.spec.ts").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.count == 2


def test_ignored_directories_not_scanned(tmp_path):
    p = tmp_path / "node_modules"
    p.mkdir()
    (p / "test_bad.py").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.test_files == ()


def test_results_are_sorted(tmp_path):
    (tmp_path / "b_test.py").write_text("")
    (tmp_path / "a_test.py").write_text("")
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.test_files == ("a_test.py", "b_test.py")


def test_empty_project_is_not_found(tmp_path):
    r = discover_tests(TestDiscoveryInput(str(tmp_path)))
    assert r.status == "NOT_FOUND"
    assert r.count == 0


def test_missing_root_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        discover_tests(TestDiscoveryInput(str(tmp_path / "missing")))


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        discover_tests(None)


def test_null_root_rejected(tmp_path):
    with pytest.raises(ValueError):
        discover_tests(TestDiscoveryInput(str(tmp_path) + "\x00bad"))
