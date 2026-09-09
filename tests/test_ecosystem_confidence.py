from dataclasses import dataclass

from sentinelshield.ecosystem_confidence import (
    score_ecosystem_confidence,
    score_ecosystem_result,
)


def test_strong_evidence_is_high():
    result = score_ecosystem_confidence(
        "python",
        ["PYPROJECT_TOML"],
    )

    assert result.score == 60
    assert result.level == "HIGH"
    assert result.evidence_count == 1
    assert result.strong_evidence_count == 1
    assert result.reason == "ECOSYSTEM_CONFIDENCE_SCORED"


def test_multiple_strong_markers_increase_score():
    result = score_ecosystem_confidence(
        "node",
        ["PACKAGE_JSON", "PACKAGE_LOCK_JSON"],
    )

    assert result.score == 100
    assert result.level == "HIGH"
    assert result.strong_evidence_count == 2


def test_medium_evidence():
    result = score_ecosystem_confidence(
        "node",
        ["NODE_SOURCE"],
    )

    assert result.score == 25
    assert result.level == "MEDIUM"


def test_medium_plus_strong_evidence():
    result = score_ecosystem_confidence(
        "python",
        ["PYPROJECT_TOML", "PYTHON_SOURCE"],
    )

    assert result.score == 85
    assert result.level == "HIGH"


def test_unknown_marker_is_low():
    result = score_ecosystem_confidence(
        "custom",
        ["UNKNOWN_MARKER"],
    )

    assert result.score == 5
    assert result.level == "LOW"


def test_no_markers():
    result = score_ecosystem_confidence(
        "python",
        [],
    )

    assert result.score == 0
    assert result.level == "NONE"
    assert result.reason == "NO_ECOSYSTEM_EVIDENCE"


def test_none_markers():
    result = score_ecosystem_confidence(
        "python",
        None,
    )

    assert result.score == 0
    assert result.level == "NONE"


def test_empty_ecosystem():
    result = score_ecosystem_confidence(
        "   ",
        ["PYPROJECT_TOML"],
    )

    assert result.reason == "ECOSYSTEM_IS_EMPTY"
    assert result.score == 0


def test_unsupported_ecosystem_type():
    result = score_ecosystem_confidence(
        123,
        ["PYPROJECT_TOML"],
    )

    assert result.reason == "UNSUPPORTED_ECOSYSTEM_TYPE"


def test_unsupported_markers_type():
    result = score_ecosystem_confidence(
        "python",
        123,
    )

    assert result.reason == "UNSUPPORTED_MARKERS_TYPE"


@dataclass
class FakeEcosystemResult:
    ecosystem: str
    marker_types: tuple[str, ...]


def test_score_existing_ecosystem_result():
    source = FakeEcosystemResult(
        "python",
        ("PYPROJECT_TOML", "PYTHON_SOURCE"),
    )

    result = score_ecosystem_result(source)

    assert result.ecosystem == "python"
    assert result.score == 85
    assert result.level == "HIGH"


def test_score_result_with_name_attribute():
    @dataclass
    class Result:
        name: str
        marker_types: tuple[str, ...]

    source = Result(
        "node",
        ("PACKAGE_JSON",),
    )

    result = score_ecosystem_result(source)

    assert result.ecosystem == "node"
    assert result.score == 60


def test_none_result():
    result = score_ecosystem_result(None)

    assert result.score == 0
    assert result.reason == "RESULT_IS_NONE"


def test_missing_ecosystem_name():
    @dataclass
    class Result:
        marker_types: tuple[str, ...]

    result = score_ecosystem_result(
        Result(("PACKAGE_JSON",))
    )

    assert result.score == 0
    assert result.reason == "ECOSYSTEM_NAME_NOT_AVAILABLE"


def test_marker_normalization():
    result = score_ecosystem_confidence(
        " Python ",
        [" pyproject_toml ", "python_source"],
    )

    assert result.ecosystem == "python"
    assert result.score == 85
    assert result.level == "HIGH"


def test_score_is_capped_at_100():
    result = score_ecosystem_confidence(
        "python",
        [
            "PYPROJECT_TOML",
            "REQUIREMENTS_TXT",
            "SETUP_PY",
            "PYTHON_SOURCE",
            "PYTHON_SOURCE",
        ],
    )

    assert result.score == 100
    assert result.level == "HIGH"
