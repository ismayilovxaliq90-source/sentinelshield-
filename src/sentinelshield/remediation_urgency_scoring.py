from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


# ============================================================
# TASK 136 — REMEDIATION URGENCY SCORING
# ============================================================

class RemediationUrgencyLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class RemediationUrgencyInput:
    severity: str | None = None
    cvss: float | int | None = None

    exploitability: bool | None = None
    reachable: bool | None = None
    runtime_exposed: bool | None = None
    production_exposed: bool | None = None
    development_dependency: bool | None = None
    internet_exposed: bool | None = None

    dependency_criticality: str | None = None
    application_impact: str | None = None

    direct_dependency: bool | None = None
    transitive_dependency: bool | None = None

    confidence_score: float | int | None = None


@dataclass(frozen=True)
class RemediationUrgencyScore:
    score: float
    level: RemediationUrgencyLevel
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RemediationUrgencyScoringResult:
    input: RemediationUrgencyInput
    result: RemediationUrgencyScore


# ============================================================
# 1. NORMALIZATION
# ============================================================

def _normalize_text(value: Any) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(
            f"Expected string or None, got {type(value).__name__}"
        )

    value = value.strip().upper()
    return value or None


def _normalize_bool(
    value: Any,
    field_name: str,
) -> bool | None:
    if value is None:
        return None

    if not isinstance(value, bool):
        raise TypeError(
            f"{field_name} must be bool or None"
        )

    return value


def _normalize_cvss(
    value: Any,
) -> float | None:
    if value is None:
        return None

    if isinstance(value, bool):
        raise TypeError("cvss must be numeric or None")

    if not isinstance(value, (int, float)):
        raise TypeError("cvss must be numeric or None")

    value = float(value)

    if not 0.0 <= value <= 10.0:
        raise ValueError(
            "cvss must be between 0 and 10"
        )

    return value


def _normalize_score(
    value: Any,
    field_name: str,
) -> float | None:
    if value is None:
        return None

    if isinstance(value, bool):
        raise TypeError(
            f"{field_name} must be numeric or None"
        )

    if not isinstance(value, (int, float)):
        raise TypeError(
            f"{field_name} must be numeric or None"
        )

    value = float(value)

    if not 0.0 <= value <= 100.0:
        raise ValueError(
            f"{field_name} must be between 0 and 100"
        )

    return value


# ============================================================
# 2. INPUT COERCION
# ============================================================

_ALLOWED_FIELDS = {
    "severity",
    "cvss",
    "exploitability",
    "reachable",
    "runtime_exposed",
    "production_exposed",
    "development_dependency",
    "internet_exposed",
    "dependency_criticality",
    "application_impact",
    "direct_dependency",
    "transitive_dependency",
    "confidence_score",
}


def _coerce_input(
    value: RemediationUrgencyInput | Mapping[str, Any],
) -> RemediationUrgencyInput:

    if isinstance(value, RemediationUrgencyInput):
        return value

    if not isinstance(value, Mapping):
        raise TypeError(
            "input must be RemediationUrgencyInput or a mapping"
        )

    unknown = set(value) - _ALLOWED_FIELDS

    if unknown:
        raise TypeError(
            "Unsupported input fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    return RemediationUrgencyInput(
        severity=value.get("severity"),
        cvss=value.get("cvss"),
        exploitability=value.get("exploitability"),
        reachable=value.get("reachable"),
        runtime_exposed=value.get("runtime_exposed"),
        production_exposed=value.get("production_exposed"),
        development_dependency=value.get(
            "development_dependency"
        ),
        internet_exposed=value.get("internet_exposed"),
        dependency_criticality=value.get(
            "dependency_criticality"
        ),
        application_impact=value.get(
            "application_impact"
        ),
        direct_dependency=value.get(
            "direct_dependency"
        ),
        transitive_dependency=value.get(
            "transitive_dependency"
        ),
        confidence_score=value.get("confidence_score"),
    )


# ============================================================
# 3. SEVERITY
# ============================================================

def _severity_points(
    severity: str | None,
) -> tuple[float, str | None]:

    if severity is None:
        return 0.0, None

    points = {
        "CRITICAL": 30.0,
        "HIGH": 22.0,
        "MEDIUM": 14.0,
        "LOW": 6.0,
        "INFORMATIONAL": 0.0,
        "INFO": 0.0,
    }

    if severity not in points:
        raise ValueError(
            f"Unsupported severity: {severity}"
        )

    result = points[severity]

    return (
        result,
        f"Severity {severity}: +{result:g}",
    )


# ============================================================
# 4. CVSS
# ============================================================

def _cvss_points(
    cvss: float | None,
) -> tuple[float, str | None]:

    if cvss is None:
        return 0.0, None

    result = round((cvss / 10.0) * 20.0, 2)

    return (
        result,
        f"CVSS {cvss:g}/10: +{result:g}",
    )


# ============================================================
# 5. BOOLEAN EVIDENCE
# ============================================================

def _boolean_points(
    value: bool | None,
    true_points: float,
    false_points: float,
    field_name: str,
) -> tuple[float, str | None]:

    if value is None:
        return 0.0, None

    result = (
        true_points
        if value
        else false_points
    )

    state = "true" if value else "false"

    return (
        result,
        f"{field_name}={state}: +{result:g}",
    )


# ============================================================
# 6. DEPENDENCY CRITICALITY
# ============================================================

def _criticality_points(
    value: str | None,
) -> tuple[float, str | None]:

    if value is None:
        return 0.0, None

    points = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
        "UNKNOWN": 0.0,
    }

    if value not in points:
        raise ValueError(
            f"Unsupported dependency criticality: {value}"
        )

    result = points[value]

    return (
        result,
        f"Dependency criticality {value}: +{result:g}",
    )


# ============================================================
# 7. APPLICATION IMPACT
# ============================================================

def _impact_points(
    value: str | None,
) -> tuple[float, str | None]:

    if value is None:
        return 0.0, None

    points = {
        "CRITICAL": 8.0,
        "HIGH": 6.0,
        "MEDIUM": 4.0,
        "LOW": 2.0,
        "NONE": 0.0,
        "UNKNOWN": 0.0,
    }

    if value not in points:
        raise ValueError(
            f"Unsupported application impact: {value}"
        )

    result = points[value]

    return (
        result,
        f"Application impact {value}: +{result:g}",
    )


# ============================================================
# 8. CONFIDENCE
# ============================================================

def _confidence_points(
    confidence_score: float | None,
) -> tuple[float, str | None]:

    if confidence_score is None:
        return 0.0, None

    result = round(
        (confidence_score / 100.0) * 5.0,
        2,
    )

    return (
        result,
        f"Evidence confidence "
        f"{confidence_score:g}/100: +{result:g}",
    )


# ============================================================
# 9. CLASSIFICATION
# ============================================================

def _classify(
    score: float,
) -> RemediationUrgencyLevel:

    if score < 25.0:
        return RemediationUrgencyLevel.LOW

    if score < 50.0:
        return RemediationUrgencyLevel.MEDIUM

    if score < 75.0:
        return RemediationUrgencyLevel.HIGH

    return RemediationUrgencyLevel.CRITICAL


# ============================================================
# 10. MAIN PUBLIC API
# ============================================================

def score_remediation_urgency(
    value: RemediationUrgencyInput | Mapping[str, Any],
) -> RemediationUrgencyScoringResult:

    raw = _coerce_input(value)

    severity = _normalize_text(raw.severity)

    dependency_criticality = _normalize_text(
        raw.dependency_criticality
    )

    application_impact = _normalize_text(
        raw.application_impact
    )

    cvss = _normalize_cvss(raw.cvss)

    exploitability = _normalize_bool(
        raw.exploitability,
        "exploitability",
    )

    reachable = _normalize_bool(
        raw.reachable,
        "reachable",
    )

    runtime_exposed = _normalize_bool(
        raw.runtime_exposed,
        "runtime_exposed",
    )

    production_exposed = _normalize_bool(
        raw.production_exposed,
        "production_exposed",
    )

    development_dependency = _normalize_bool(
        raw.development_dependency,
        "development_dependency",
    )

    internet_exposed = _normalize_bool(
        raw.internet_exposed,
        "internet_exposed",
    )

    direct_dependency = _normalize_bool(
        raw.direct_dependency,
        "direct_dependency",
    )

    transitive_dependency = _normalize_bool(
        raw.transitive_dependency,
        "transitive_dependency",
    )

    confidence_score = _normalize_score(
        raw.confidence_score,
        "confidence_score",
    )

    normalized = RemediationUrgencyInput(
        severity=severity,
        cvss=cvss,
        exploitability=exploitability,
        reachable=reachable,
        runtime_exposed=runtime_exposed,
        production_exposed=production_exposed,
        development_dependency=development_dependency,
        internet_exposed=internet_exposed,
        dependency_criticality=dependency_criticality,
        application_impact=application_impact,
        direct_dependency=direct_dependency,
        transitive_dependency=transitive_dependency,
        confidence_score=confidence_score,
    )

    total = 0.0
    reasons: list[str] = []

    # Severity
    points, reason = _severity_points(severity)
    total += points

    if reason:
        reasons.append(reason)

    # CVSS
    points, reason = _cvss_points(cvss)
    total += points

    if reason:
        reasons.append(reason)

    # Exploitability
    points, reason = _boolean_points(
        exploitability,
        true_points=8.0,
        false_points=2.0,
        field_name="Exploitability",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Reachability
    points, reason = _boolean_points(
        reachable,
        true_points=7.0,
        false_points=1.0,
        field_name="Reachability",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Runtime exposure
    points, reason = _boolean_points(
        runtime_exposed,
        true_points=6.0,
        false_points=1.0,
        field_name="Runtime exposure",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Production exposure
    points, reason = _boolean_points(
        production_exposed,
        true_points=8.0,
        false_points=1.0,
        field_name="Production exposure",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Internet exposure
    points, reason = _boolean_points(
        internet_exposed,
        true_points=7.0,
        false_points=1.0,
        field_name="Internet exposure",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Dependency criticality
    points, reason = _criticality_points(
        dependency_criticality
    )
    total += points

    if reason:
        reasons.append(reason)

    # Application impact
    points, reason = _impact_points(
        application_impact
    )
    total += points

    if reason:
        reasons.append(reason)

    # Direct dependency
    points, reason = _boolean_points(
        direct_dependency,
        true_points=4.0,
        false_points=0.0,
        field_name="Direct dependency",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Transitive dependency
    points, reason = _boolean_points(
        transitive_dependency,
        true_points=2.0,
        false_points=0.0,
        field_name="Transitive dependency",
    )
    total += points

    if reason:
        reasons.append(reason)

    # Development dependency
    if development_dependency is not None:
        points = (
            1.0
            if development_dependency
            else 0.0
        )

        state = (
            "true"
            if development_dependency
            else "false"
        )

        total += points

        reasons.append(
            f"Development dependency={state}: "
            f"+{points:g}"
        )

    # Evidence confidence
    points, reason = _confidence_points(
        confidence_score
    )
    total += points

    if reason:
        reasons.append(reason)

    # Final score contract
    score = max(
        0.0,
        min(
            100.0,
            round(total, 2),
        ),
    )

    level = _classify(score)

    reasons.append(
        f"Final remediation urgency score: "
        f"{score:.2f}/100 ({level.value})"
    )

    return RemediationUrgencyScoringResult(
        input=normalized,
        result=RemediationUrgencyScore(
            score=score,
            level=level,
            reasons=tuple(reasons),
        ),
    )


# ============================================================
# 11. PUBLIC ALIAS
# ============================================================

remediation_urgency_scoring = (
    score_remediation_urgency
)


# ============================================================
# 12. INTERNAL IMPLEMENTATION CHECK
# ============================================================

def _implementation_check() -> None:

    empty = score_remediation_urgency({})

    assert empty.result.score == 0.0
    assert (
        empty.result.level
        is RemediationUrgencyLevel.LOW
    )

    critical = score_remediation_urgency(
        {
            "severity": "CRITICAL",
            "cvss": 10,
            "exploitability": True,
            "reachable": True,
            "runtime_exposed": True,
            "production_exposed": True,
            "internet_exposed": True,
            "dependency_criticality": "CRITICAL",
            "application_impact": "CRITICAL",
            "direct_dependency": True,
            "transitive_dependency": True,
            "development_dependency": False,
            "confidence_score": 100,
        }
    )

    assert (
        0.0
        <= critical.result.score
        <= 100.0
    )

    assert (
        critical.result.level
        is RemediationUrgencyLevel.CRITICAL
    )

    low_cvss = score_remediation_urgency(
        {"cvss": 2}
    )

    high_cvss = score_remediation_urgency(
        {"cvss": 8}
    )

    assert (
        high_cvss.result.score
        > low_cvss.result.score
    )

    low_severity = score_remediation_urgency(
        {"severity": "LOW"}
    )

    high_severity = score_remediation_urgency(
        {"severity": "HIGH"}
    )

    assert (
        high_severity.result.score
        > low_severity.result.score
    )

    assert (
        score_remediation_urgency(
            {"exploitability": True}
        ).result.score
        >
        score_remediation_urgency(
            {"exploitability": False}
        ).result.score
    )

    assert (
        score_remediation_urgency(
            {"reachable": True}
        ).result.score
        >
        score_remediation_urgency(
            {"reachable": False}
        ).result.score
    )

    assert (
        score_remediation_urgency(
            {"production_exposed": True}
        ).result.score
        >
        score_remediation_urgency(
            {"production_exposed": False}
        ).result.score
    )

    assert (
        score_remediation_urgency(
            {"internet_exposed": True}
        ).result.score
        >
        score_remediation_urgency(
            {"internet_exposed": False}
        ).result.score
    )

    assert (
        score_remediation_urgency(
            {"confidence_score": 90}
        ).result.score
        >
        score_remediation_urgency(
            {"confidence_score": 20}
        ).result.score
    )

    mapped = score_remediation_urgency(
        {
            "severity": "HIGH",
            "cvss": 8,
            "reachable": True,
        }
    )

    assert isinstance(
        mapped.result.score,
        float,
    )

    assert isinstance(
        mapped.result.level,
        RemediationUrgencyLevel,
    )

    assert isinstance(
        mapped.result.reasons,
        tuple,
    )

    sample = {
        "severity": "HIGH",
        "cvss": 7.5,
        "exploitability": True,
        "reachable": True,
        "production_exposed": True,
        "confidence_score": 80,
    }

    first = score_remediation_urgency(sample)
    second = score_remediation_urgency(sample)

    assert first == second

    try:
        score_remediation_urgency(
            {"cvss": 10.1}
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "CVSS > 10 was not rejected"
        )

    try:
        score_remediation_urgency(
            {"cvss": -0.1}
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "CVSS < 0 was not rejected"
        )

    try:
        score_remediation_urgency(
            {"exploitability": "true"}
        )
    except TypeError:
        pass
    else:
        raise AssertionError(
            "Invalid boolean was not rejected"
        )

    try:
        score_remediation_urgency(
            {"confidence_score": 101}
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Confidence > 100 was not rejected"
        )

    try:
        score_remediation_urgency(
            {"unknown_field": True}
        )
    except TypeError:
        pass
    else:
        raise AssertionError(
            "Unknown field was not rejected"
        )

    normalized = score_remediation_urgency(
        {
            "severity": "  high ",
            "dependency_criticality": " high ",
            "application_impact": " HIGH ",
        }
    )

    canonical = score_remediation_urgency(
        {
            "severity": "HIGH",
            "dependency_criticality": "HIGH",
            "application_impact": "HIGH",
        }
    )

    assert normalized == canonical


# ============================================================
# 13. RUN IMPLEMENTATION CHECK
# ============================================================

_implementation_check()

print("=" * 60)
print("TASK 136 — REMEDIATION URGENCY SCORING")
print("=" * 60)
print("IMPLEMENTATION: PASS")
print("PUBLIC API: PASS")
print("INPUT VALIDATION: PASS")
print("SCORING MODEL: PASS")
print("CLASSIFICATION: PASS")
print("DETERMINISM: PASS")
print("MAPPING INPUT: PASS")
print("BOUNDARY VALIDATION: PASS")
print("STATUS: VERIFIED")
print("WSL SESSION REMAINS OPEN")
print("=" * 60)
