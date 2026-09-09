from pathlib import Path

from sentinelshield.pom_xml_discovery import (
    PomXmlDiscovery,
    PomXmlDiscoveryResult,
    discover_pom_xml,
)


def test_pom_xml_is_discovered(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert isinstance(result, PomXmlDiscoveryResult)
    assert result.discovered is True
    assert result.files == (pom.resolve(),)
    assert result.reason == "POM_XML_DISCOVERY_SUCCESS"


def test_nested_pom_xml_is_discovered(tmp_path):
    pom = tmp_path / "module" / "pom.xml"
    pom.parent.mkdir()
    pom.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert result.discovered is True
    assert result.files == (pom.resolve(),)


def test_multiple_pom_xml_files_are_discovered(tmp_path):
    pom1 = tmp_path / "pom.xml"
    pom2 = tmp_path / "module" / "pom.xml"

    pom2.parent.mkdir()

    pom1.write_text("<project/>", encoding="utf-8")
    pom2.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert result.discovered is True
    assert result.files == tuple(
        sorted(
            (pom1.resolve(), pom2.resolve()),
            key=lambda path: path.as_posix(),
        )
    )


def test_missing_pom_xml_returns_not_found(tmp_path):
    result = discover_pom_xml(tmp_path)

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "POM_XML_NOT_FOUND"


def test_none_project_path_is_rejected():
    result = discover_pom_xml(None)

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "PROJECT_PATH_IS_NONE"


def test_empty_project_path_is_rejected():
    result = discover_pom_xml("")

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_whitespace_project_path_is_rejected():
    result = discover_pom_xml("   ")

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "PROJECT_PATH_IS_EMPTY"


def test_unsupported_project_path_type_is_rejected():
    result = discover_pom_xml(123)

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "UNSUPPORTED_PROJECT_PATH_TYPE"


def test_file_path_is_rejected(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("data", encoding="utf-8")

    result = discover_pom_xml(file_path)

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "PROJECT_PATH_NOT_DIRECTORY"


def test_nonexistent_path_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = discover_pom_xml(missing)

    assert result.discovered is False
    assert result.files == ()
    assert result.reason == "PROJECT_PATH_NOT_FOUND"


def test_string_project_path_is_supported(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(str(tmp_path))

    assert result.discovered is True
    assert result.files == (pom.resolve(),)


def test_path_object_is_supported(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    result = PomXmlDiscovery().discover(tmp_path)

    assert result.discovered is True
    assert result.files == (pom.resolve(),)


def test_discovery_does_not_modify_filesystem(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_pom_xml(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.discovered is True
    assert before == after


def test_only_exact_pom_xml_filename_is_discovered(tmp_path):
    valid = tmp_path / "pom.xml"
    invalid1 = tmp_path / "POM.XML"
    invalid2 = tmp_path / "pom.xml.bak"

    valid.write_text("<project/>", encoding="utf-8")
    invalid1.write_text("<project/>", encoding="utf-8")
    invalid2.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert result.discovered is True
    assert result.files == (valid.resolve(),)


def test_result_files_are_tuple(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert isinstance(result.files, tuple)


def test_result_is_immutable(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<project/>", encoding="utf-8")

    result = discover_pom_xml(tmp_path)

    assert result.discovered is True

    try:
        result.discovered = False
        raise AssertionError("Result must be immutable")
    except AttributeError:
        pass
