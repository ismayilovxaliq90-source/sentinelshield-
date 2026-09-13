import pytest

from sentinelshield.blast_radius_re_evaluation import (
    BlastRadiusReEvaluationInput,
    re_evaluate_blast_radius,
)


def test_changed_dependency_affects_direct_parent():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"requests"},
                "requests": {"urllib3"},
            },
            changed_packages={"urllib3"},
        )
    )

    assert result.affected_packages == (
        "app",
        "requests",
        "urllib3",
    )


def test_transitive_blast_radius_is_calculated():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"service"},
                "service": {"library"},
                "library": {"core"},
            },
            changed_packages={"core"},
        )
    )

    assert result.affected_packages == (
        "app",
        "core",
        "library",
        "service",
    )


def test_unrelated_branch_is_not_affected():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"a", "b"},
                "a": {"changed"},
                "b": {"unrelated"},
            },
            changed_packages={"changed"},
        )
    )

    assert result.affected_packages == (
        "a",
        "app",
        "changed",
    )
    assert "b" not in result.affected_packages


def test_newly_affected_packages_are_detected():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"requests"},
                "requests": {"urllib3"},
            },
            changed_packages={"urllib3"},
            previous_blast_radius={"urllib3"},
        )
    )

    assert result.newly_affected == ("app", "requests")


def test_no_longer_affected_packages_are_detected():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"requests"},
            },
            changed_packages={"requests"},
            previous_blast_radius={
                "app",
                "requests",
                "old-package",
            },
        )
    )

    assert result.no_longer_affected == ("old-package",)


def test_unchanged_blast_radius():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"requests"},
            },
            changed_packages={"requests"},
            previous_blast_radius={
                "app",
                "requests",
            },
        )
    )

    assert result.status == "UNCHANGED"
    assert result.changed is False


def test_package_names_are_normalized():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "My_App": {"My_Dep"},
            },
            changed_packages={"my_dep"},
        )
    )

    assert result.affected_packages == (
        "my-app",
        "my-dep",
    )


def test_empty_change_set_has_no_affected_packages():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={"app": {"requests"}},
            changed_packages=set(),
        )
    )

    assert result.affected_packages == ()
    assert result.status == "UNCHANGED"


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_BLAST_RADIUS_RE_EVALUATION_INPUT",
    ):
        re_evaluate_blast_radius(None)


def test_self_dependency_is_not_required_for_traversal():
    result = re_evaluate_blast_radius(
        BlastRadiusReEvaluationInput(
            dependency_tree={
                "app": {"library"},
                "library": set(),
            },
            changed_packages={"library"},
        )
    )

    assert result.affected_packages == (
        "app",
        "library",
    )
