import pytest

from sentinelshield.dependency_import_validation import (
    DependencyImportValidationInput,
    validate_dependency_imports,
)


def test_existing_import_passes():
    r = validate_dependency_imports(
        DependencyImportValidationInput(("json", "pathlib"))
    )
    assert r.status == "PASS"
    assert r.valid == ("json", "pathlib")
    assert r.invalid == ()


def test_missing_import_fails():
    r = validate_dependency_imports(
        DependencyImportValidationInput(("module_that_does_not_exist_xyz",))
    )
    assert r.status == "FAIL"
    assert r.invalid == ("module_that_does_not_exist_xyz",)


def test_mixed_imports():
    r = validate_dependency_imports(
        DependencyImportValidationInput(("json", "module_that_does_not_exist_xyz"))
    )
    assert r.status == "FAIL"
    assert "json" in r.valid
    assert "module_that_does_not_exist_xyz" in r.invalid


def test_duplicates_are_removed():
    r = validate_dependency_imports(
        DependencyImportValidationInput(("json", "json"))
    )
    assert r.valid == ("json",)


def test_names_are_sorted():
    r = validate_dependency_imports(
        DependencyImportValidationInput(("pathlib", "json"))
    )
    assert r.valid == ("json", "pathlib")


def test_non_tuple_rejected():
    with pytest.raises(TypeError):
        validate_dependency_imports(
            DependencyImportValidationInput(["json"])
        )


def test_non_string_rejected():
    with pytest.raises(TypeError):
        validate_dependency_imports(
            DependencyImportValidationInput(("json", 1))
        )


def test_empty_name_rejected():
    with pytest.raises(ValueError):
        validate_dependency_imports(
            DependencyImportValidationInput((" ",))
        )


def test_null_name_rejected():
    with pytest.raises(ValueError):
        validate_dependency_imports(
            DependencyImportValidationInput(("json\x00bad",))
        )


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        validate_dependency_imports(None)
