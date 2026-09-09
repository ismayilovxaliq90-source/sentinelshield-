from dataclasses import dataclass

from sentinelshield.version_constraint_extraction import (
    VersionConstraintDependency,
    VersionConstraintExtractionResult,
    extract_version_constraints,
)


@dataclass
class Dependency:
    name: str
    dependency_type: str = "production"
    version_constraint: str | None = None
    constraint: str | None = None
    specifier: str | None = None
    version_spec: str | None = None
    requirement: str | None = None
    source: str | None = None


def test_extracts_version_constraint():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=">=2.31,<3")]
    )

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        VersionConstraintDependency(
            "requests",
            ">=2.31,<3",
            "production",
        ),
    )


def test_constraint_field_is_supported():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=None, constraint=">=2.0")]
    )

    assert result.dependencies[0].constraint == ">=2.0"


def test_specifier_field_is_supported():
    result = extract_version_constraints(
        [Dependency("requests", specifier="~=2.31")]
    )

    assert result.dependencies[0].constraint == "~=2.31"


def test_version_spec_field_is_supported():
    result = extract_version_constraints(
        [Dependency("requests", version_spec="^2.31")]
    )

    assert result.dependencies[0].constraint == "^2.31"


def test_requirement_field_is_supported():
    result = extract_version_constraints(
        [Dependency("requests", requirement=">=2.31")]
    )

    assert result.dependencies[0].constraint == ">=2.31"


def test_constraint_field_priority_is_deterministic():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                version_constraint=">=2.31",
                constraint="<3",
                specifier="~=2.31",
            )
        ]
    )

    assert result.dependencies[0].constraint == ">=2.31"


def test_whitespace_is_normalized():
    result = extract_version_constraints(
        [Dependency("  requests  ", version_constraint="  >=2.31  ")]
    )

    assert result.dependencies[0].name == "requests"
    assert result.dependencies[0].constraint == ">=2.31"


def test_dependency_type_is_normalized():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                dependency_type="  PRODUCTION  ",
                version_constraint=">=2.31",
            )
        ]
    )

    assert result.dependencies[0].dependency_type == "production"


def test_none_collection_is_rejected():
    result = extract_version_constraints(None)

    assert result.extracted is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_collection_is_rejected():
    result = extract_version_constraints("requests")

    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_collection_is_rejected():
    result = extract_version_constraints(b"requests")

    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_is_rejected():
    result = extract_version_constraints(123)

    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_none_dependency_is_rejected():
    result = extract_version_constraints([None])

    assert result.status == "INVALID_DEPENDENCY"


def test_missing_name_is_rejected():
    class Invalid:
        version_constraint = ">=1.0"
        dependency_type = "production"

    result = extract_version_constraints([Invalid()])

    assert result.status == "INVALID_DEPENDENCY"


def test_empty_name_is_rejected():
    result = extract_version_constraints(
        [Dependency("   ", version_constraint=">=1.0")]
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_missing_constraint_is_rejected():
    result = extract_version_constraints(
        [Dependency("requests")]
    )

    assert result.status == "CONSTRAINT_NOT_AVAILABLE"


def test_none_constraint_falls_back_to_next_field():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                version_constraint=None,
                constraint=">=2.0",
            )
        ]
    )

    assert result.status == "EXTRACTED"
    assert result.dependencies[0].constraint == ">=2.0"


def test_empty_constraint_is_rejected():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint="   ")]
    )

    assert result.status == "CONSTRAINT_EMPTY"


def test_invalid_constraint_type_is_rejected():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=123)]
    )

    assert result.status == "INVALID_VERSION_CONSTRAINT"


def test_invalid_dependency_type_is_rejected():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                dependency_type=123,
                version_constraint=">=2.0",
            )
        ]
    )

    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_source_is_rejected():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                version_constraint=">=2.0",
                source=123,
            )
        ]
    )

    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_source_is_preserved():
    result = extract_version_constraints(
        [
            Dependency(
                "requests",
                version_constraint=">=2.0",
                source="pypi",
            )
        ]
    )

    assert result.dependencies[0].source == "pypi"


def test_duplicates_are_removed():
    result = extract_version_constraints(
        [
            Dependency("requests", version_constraint=">=2.0"),
            Dependency("requests", version_constraint=">=2.0"),
        ]
    )

    assert len(result.dependencies) == 1


def test_deterministic_sorting():
    result = extract_version_constraints(
        [
            Dependency("zlib", version_constraint=">=1"),
            Dependency("axios", version_constraint="^1"),
            Dependency("express", version_constraint="^4"),
            Dependency("Axios", version_constraint="^2"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "axios",
        "Axios",
        "express",
        "zlib",
    ]


def test_different_constraints_are_preserved():
    result = extract_version_constraints(
        [
            Dependency("requests", version_constraint=">=2.0"),
            Dependency("requests", version_constraint="<3.0"),
        ]
    )

    assert [item.constraint for item in result.dependencies] == [
        "<3.0",
        ">=2.0",
    ]


def test_input_is_not_modified():
    original = Dependency(
        "  requests  ",
        dependency_type=" PRODUCTION ",
        version_constraint=" >=2.0 ",
    )

    extract_version_constraints([original])

    assert original.name == "  requests  "
    assert original.dependency_type == " PRODUCTION "
    assert original.version_constraint == " >=2.0 "


def test_result_is_immutable():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=">=2.0")]
    )

    try:
        result.extracted = False
        assert False, "Result must be immutable"
    except AttributeError:
        pass


def test_dependency_result_is_immutable():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=">=2.0")]
    )

    try:
        result.dependencies[0].constraint = ">=3.0"
        assert False, "Dependency result must be immutable"
    except AttributeError:
        pass


def test_result_type_is_correct():
    result = extract_version_constraints(
        [Dependency("requests", version_constraint=">=2.0")]
    )

    assert isinstance(result, VersionConstraintExtractionResult)
    assert isinstance(result.dependencies[0], VersionConstraintDependency)


def test_common_constraint_forms_are_preserved():
    constraints = [
        "==1.2.3",
        ">=1.2,<2.0",
        "^1.2.3",
        "~1.2.3",
        "~=1.2.3",
        "*",
        "1.2.3",
    ]

    result = extract_version_constraints(
        [
            Dependency(
                f"pkg-{index}",
                version_constraint=constraint,
            )
            for index, constraint in enumerate(constraints)
        ]
    )

    assert [item.constraint for item in result.dependencies] == [
        "==1.2.3",
        ">=1.2,<2.0",
        "^1.2.3",
        "~1.2.3",
        "~=1.2.3",
        "*",
        "1.2.3",
    ]
