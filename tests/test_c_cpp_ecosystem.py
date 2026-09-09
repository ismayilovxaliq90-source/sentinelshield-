from sentinelshield.c_cpp_ecosystem import detect_c_cpp_ecosystem


def test_cmake_high_confidence(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"
    assert r.marker_types["CMakeLists.txt"] == "CMAKE"


def test_makefile_high_confidence(tmp_path):
    (tmp_path / "Makefile").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "HIGH"


def test_lowercase_makefile_high_confidence(tmp_path):
    (tmp_path / "makefile").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_gnumakefile_high_confidence(tmp_path):
    (tmp_path / "GNUmakefile").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_meson_high_confidence(tmp_path):
    (tmp_path / "meson.build").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_autoconf_high_confidence(tmp_path):
    (tmp_path / "configure.ac").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_conan_high_confidence(tmp_path):
    (tmp_path / "conanfile.py").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_vcpkg_high_confidence(tmp_path):
    (tmp_path / "vcpkg.json").write_text("{}")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"


def test_vcxproj_high_confidence(tmp_path):
    (tmp_path / "App.vcxproj").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.confidence == "HIGH"
    assert r.marker_types["App.vcxproj"] == "VCXPROJ"


def test_solution_medium_confidence(tmp_path):
    (tmp_path / "App.sln").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types["App.sln"] == "SLN"


def test_c_source_medium(tmp_path):
    (tmp_path / "main.c").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.confidence == "MEDIUM"
    assert r.marker_types["main.c"] == "SOURCE"


def test_cpp_source_medium(tmp_path):
    (tmp_path / "main.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.marker_types["main.cpp"] == "SOURCE"


def test_cpp_variants(tmp_path):
    for name in ("a.cc", "b.cxx", "c.hpp", "d.hxx", "e.ixx"):
        (tmp_path / name).write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert len(r.markers) == 5
    assert all(v == "SOURCE" for v in r.marker_types.values())


def test_header_source(tmp_path):
    (tmp_path / "main.h").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.detected
    assert r.marker_types["main.h"] == "SOURCE"


def test_nested_project(tmp_path):
    project = tmp_path / "src" / "native"
    project.mkdir(parents=True)
    (project / "CMakeLists.txt").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.markers == ["src/native/CMakeLists.txt"]


def test_multiple_markers_sorted(tmp_path):
    (tmp_path / "Z.cpp").write_text("")
    (tmp_path / "CMakeLists.txt").write_text("")
    (tmp_path / "A.c").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.markers == ["A.c", "CMakeLists.txt", "Z.cpp"]


def test_build_ignored(tmp_path):
    d = tmp_path / "build"
    d.mkdir()
    (d / "Fake.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected


def test_cmake_build_ignored(tmp_path):
    d = tmp_path / "cmake-build-debug"
    d.mkdir()
    (d / "Fake.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected


def test_node_modules_ignored(tmp_path):
    d = tmp_path / "node_modules"
    d.mkdir()
    (d / "Fake.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected


def test_git_ignored(tmp_path):
    d = tmp_path / ".git"
    d.mkdir()
    (d / "Fake.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected


def test_bin_obj_ignored(tmp_path):
    for name in ("bin", "obj"):
        d = tmp_path / name
        d.mkdir()
        (d / "Fake.cpp").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected


def test_symlink_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "Real.cpp").write_text("")
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        return
    r = detect_c_cpp_ecosystem(tmp_path)
    assert r.markers == ["real/Real.cpp"]


def test_non_cpp_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "main.py").write_text("")
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected
    assert r.confidence == "NONE"


def test_empty_project(tmp_path):
    r = detect_c_cpp_ecosystem(tmp_path)
    assert not r.detected
    assert r.reason == "C_CPP_ECOSYSTEM_NOT_DETECTED"


def test_none_path():
    r = detect_c_cpp_ecosystem(None)
    assert r.reason == "PATH_IS_NONE"


def test_empty_path():
    r = detect_c_cpp_ecosystem("   ")
    assert r.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    r = detect_c_cpp_ecosystem(123)
    assert r.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character(tmp_path):
    r = detect_c_cpp_ecosystem(str(tmp_path) + "\x00evil")
    assert r.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    r = detect_c_cpp_ecosystem(tmp_path / "missing")
    assert r.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("")
    r = detect_c_cpp_ecosystem(f)
    assert r.reason == "PATH_IS_NOT_DIRECTORY"
