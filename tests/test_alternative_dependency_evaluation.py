import pytest

from sentinelshield.alternative_dependency_evaluation import (
    AlternativeDependency,
    AlternativeDependencyEvaluation,
    AlternativeDependencyEvaluationResult,
    alternative_dependency_evaluation,
    evaluate_alternative_dependencies,
    evaluate_dependency_alternatives,
)


def test_evaluates_alternative():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="2.0.0",
                security_score=90,
                compatibility_score=85,
                maintenance_score=80,
                migration_effort=20,
            )
        ]
    )

    assert result.total == 1
    assert result.recommended_package == "safe-lib"
    assert result.recommended_version == "2.0.0"


def test_evaluation_score_formula():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="2.0.0",
                security_score=90,
                compatibility_score=80,
                maintenance_score=70,
                migration_effort=20,
            )
        ]
    )

    # 90*.35 + 80*.30 + 70*.20 + 80*.15 = 82.5
    assert result.evaluations[0].evaluation_score == 81.5


def test_highest_score_is_recommended():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="weak-lib",
                candidate_version="1.0.0",
                security_score=50,
                compatibility_score=50,
                maintenance_score=50,
                migration_effort=70,
            ),
            AlternativeDependency(
                package_name="strong-lib",
                candidate_version="2.0.0",
                security_score=95,
                compatibility_score=90,
                maintenance_score=90,
                migration_effort=10,
            ),
        ]
    )

    assert result.evaluations[0].package_name == "strong-lib"
    assert result.evaluations[0].recommended is True
    assert result.evaluations[1].recommended is False


def test_migration_effort_is_a_penalty():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="low-migration",
                candidate_version="1.0.0",
                security_score=80,
                compatibility_score=80,
                maintenance_score=80,
                migration_effort=10,
            ),
            AlternativeDependency(
                package_name="high-migration",
                candidate_version="1.0.0",
                security_score=80,
                compatibility_score=80,
                maintenance_score=80,
                migration_effort=90,
            ),
        ]
    )

    assert (
        result.evaluations[0].evaluation_score
        > result.evaluations[1].evaluation_score
    )


def test_reasons_are_generated():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="1.0.0",
                security_score=90,
                compatibility_score=90,
                maintenance_score=90,
                migration_effort=10,
            )
        ]
    )

    reasons = result.evaluations[0].reasons

    assert "STRONG_SECURITY" in reasons
    assert "STRONG_COMPATIBILITY" in reasons
    assert "STRONG_MAINTENANCE" in reasons
    assert "LOW_MIGRATION_EFFORT" in reasons


def test_concern_reasons_are_generated():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="weak-lib",
                candidate_version="1.0.0",
                security_score=20,
                compatibility_score=20,
                maintenance_score=20,
                migration_effort=90,
            )
        ]
    )

    reasons = result.evaluations[0].reasons

    assert "SECURITY_CONCERN" in reasons
    assert "COMPATIBILITY_CONCERN" in reasons
    assert "MAINTENANCE_CONCERN" in reasons
    assert "HIGH_MIGRATION_EFFORT" in reasons


def test_duplicate_semantic_versions_are_removed():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="1.2.3",
            ),
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="v1.2.3",
            ),
        ]
    )

    assert result.total == 1


def test_different_packages_are_not_duplicates():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="lib-a",
                candidate_version="1.0.0",
            ),
            AlternativeDependency(
                package_name="lib-b",
                candidate_version="1.0.0",
            ),
        ]
    )

    assert result.total == 2


def test_empty_input():
    result = evaluate_alternative_dependencies([])

    assert result.evaluations == ()
    assert result.total == 0
    assert result.recommended_package is None
    assert result.recommended_version is None


def test_result_dataclass():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="safe-lib",
                candidate_version="1.0.0",
            )
        ]
    )

    assert isinstance(
        result,
        AlternativeDependencyEvaluationResult,
    )
    assert isinstance(
        result.evaluations[0],
        AlternativeDependencyEvaluation,
    )


def test_invalid_collection_type():
    with pytest.raises(
        TypeError,
        match="ALTERNATIVES_MUST_BE_SEQUENCE",
    ):
        evaluate_alternative_dependencies("invalid")


def test_invalid_item_type():
    with pytest.raises(
        TypeError,
        match="ALTERNATIVE_MUST_BE_ALTERNATIVE_DEPENDENCY:0",
    ):
        evaluate_alternative_dependencies([{}])


def test_invalid_package_name():
    with pytest.raises(
        TypeError,
        match="PACKAGE_NAME_MUST_BE_STRING",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name=123,
                    candidate_version="1.0.0",
                )
            ]
        )


def test_empty_package_name():
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAME_IS_EMPTY",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name=" ",
                    candidate_version="1.0.0",
                )
            ]
        )


def test_invalid_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name="safe-lib",
                    candidate_version="1.x.0",
                )
            ]
        )


def test_invalid_security_score_type():
    with pytest.raises(
        TypeError,
        match="SECURITY_SCORE_MUST_BE_NUMERIC",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name="safe-lib",
                    candidate_version="1.0.0",
                    security_score="90",
                )
            ]
        )


def test_invalid_score_range():
    with pytest.raises(
        ValueError,
        match="SECURITY_SCORE_OUT_OF_RANGE",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name="safe-lib",
                    candidate_version="1.0.0",
                    security_score=101,
                )
            ]
        )


def test_invalid_migration_effort_range():
    with pytest.raises(
        ValueError,
        match="MIGRATION_EFFORT_OUT_OF_RANGE",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name="safe-lib",
                    candidate_version="1.0.0",
                    migration_effort=-1,
                )
            ]
        )


def test_boolean_score_is_rejected():
    with pytest.raises(
        TypeError,
        match="SECURITY_SCORE_MUST_BE_NUMERIC",
    ):
        evaluate_alternative_dependencies(
            [
                AlternativeDependency(
                    package_name="safe-lib",
                    candidate_version="1.0.0",
                    security_score=True,
                )
            ]
        )


def test_deterministic_ordering():
    alternatives = [
        AlternativeDependency(
            package_name="z-lib",
            candidate_version="1.0.0",
            security_score=80,
            compatibility_score=80,
            maintenance_score=80,
            migration_effort=20,
        ),
        AlternativeDependency(
            package_name="a-lib",
            candidate_version="1.0.0",
            security_score=80,
            compatibility_score=80,
            maintenance_score=80,
            migration_effort=20,
        ),
    ]

    first = evaluate_alternative_dependencies(alternatives)
    second = evaluate_alternative_dependencies(alternatives)

    assert first == second
    assert [
        item.package_name for item in first.evaluations
    ] == ["a-lib", "z-lib"]


def test_input_is_not_modified():
    alternatives = [
        AlternativeDependency(
            package_name="a-lib",
            candidate_version="1.0.0",
        ),
        AlternativeDependency(
            package_name="b-lib",
            candidate_version="2.0.0",
        ),
    ]

    original = list(alternatives)

    evaluate_alternative_dependencies(alternatives)

    assert alternatives == original


def test_public_aliases():
    assert (
        alternative_dependency_evaluation
        is evaluate_alternative_dependencies
    )

    assert (
        evaluate_dependency_alternatives
        is evaluate_alternative_dependencies
    )


def test_recommended_only_for_best_candidate():
    result = evaluate_alternative_dependencies(
        [
            AlternativeDependency(
                package_name="a-lib",
                candidate_version="1.0.0",
                security_score=90,
                compatibility_score=90,
                maintenance_score=90,
                migration_effort=10,
            ),
            AlternativeDependency(
                package_name="b-lib",
                candidate_version="1.0.0",
                security_score=50,
                compatibility_score=50,
                maintenance_score=50,
                migration_effort=50,
            ),
        ]
    )

    assert sum(
        item.recommended for item in result.evaluations
    ) == 1
