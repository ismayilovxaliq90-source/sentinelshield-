from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class EcosystemConfidenceResult:
    ecosystem: str
    score: int
    level: str
    evidence_count: int
    strong_evidence_count: int
    reason: str


STRONG_MARKERS = {
    "PACKAGE_JSON",
    "PACKAGE_LOCK_JSON",
    "NPM_SHRINKWRAP",
    "YARN_LOCK",
    "PNPM_LOCK",
    "BUN_LOCK",
    "PYPROJECT_TOML",
    "REQUIREMENTS_TXT",
    "PIPFILE",
    "SETUP_PY",
    "SETUP_CFG",
    "POETRY_LOCK",
    "UV_LOCK",
    "POM_XML",
    "BUILD_GRADLE",
    "BUILD_GRADLE_KTS",
    "GO_MOD",
    "CARGO_TOML",
    "COMPOSER_JSON",
    "GEMFILE",
    "DOTNET_PROJECT",
    "CMAKE",
    "MAKEFILE",
}

MEDIUM_MARKERS = {
    "NVMRC",
    "NODE_VERSION",
    "PYTHON_SOURCE",
    "NODE_SOURCE",
    "JAVA_SOURCE",
    "GO_SOURCE",
    "RUST_SOURCE",
    "PHP_SOURCE",
    "RUBY_SOURCE",
    "DOTNET_SOURCE",
    "CPP_SOURCE",
}


def _normalise_markers(markers: Iterable[Any]) -> tuple[str, ...]:
    result: list[str] = []

    for marker in markers:
        if isinstance(marker, str):
            value = marker.strip().upper()
            if value:
                result.append(value)

    return tuple(result)


def score_ecosystem_confidence(
    ecosystem: Any,
    markers: Iterable[Any] | None,
) -> EcosystemConfidenceResult:
    if not isinstance(ecosystem, str):
        return EcosystemConfidenceResult(
            "unknown", 0, "NONE", 0, 0,
            "UNSUPPORTED_ECOSYSTEM_TYPE",
        )

    ecosystem = ecosystem.strip().lower()

    if not ecosystem:
        return EcosystemConfidenceResult(
            "", 0, "NONE", 0, 0,
            "ECOSYSTEM_IS_EMPTY",
        )

    if markers is None:
        marker_values: tuple[str, ...] = ()
    else:
        try:
            marker_values = _normalise_markers(markers)
        except TypeError:
            return EcosystemConfidenceResult(
                ecosystem, 0, "NONE", 0, 0,
                "UNSUPPORTED_MARKERS_TYPE",
            )

    if not marker_values:
        return EcosystemConfidenceResult(
            ecosystem, 0, "NONE", 0, 0,
            "NO_ECOSYSTEM_EVIDENCE",
        )

    strong_count = sum(
        marker in STRONG_MARKERS
        for marker in marker_values
    )

    medium_count = sum(
        marker in MEDIUM_MARKERS
        for marker in marker_values
    )

    unknown_count = len(marker_values) - strong_count - medium_count

    # Strong evidence has the highest weight.
    # Multiple independent markers increase confidence,
    # but the score is capped at 100.
    score = min(
        100,
        strong_count * 60
        + medium_count * 25
        + unknown_count * 5,
    )

    if strong_count:
        level = "HIGH"
    elif medium_count:
        level = "MEDIUM"
    else:
        level = "LOW"

    return EcosystemConfidenceResult(
        ecosystem=ecosystem,
        score=score,
        level=level,
        evidence_count=len(marker_values),
        strong_evidence_count=strong_count,
        reason="ECOSYSTEM_CONFIDENCE_SCORED",
    )


def score_ecosystem_result(result: Any) -> EcosystemConfidenceResult:
    if result is None:
        return EcosystemConfidenceResult(
            "unknown", 0, "NONE", 0, 0,
            "RESULT_IS_NONE",
        )

    ecosystem = getattr(result, "ecosystem", None)

    if ecosystem is None:
        ecosystem = getattr(result, "name", None)

    markers = getattr(result, "marker_types", None)

    if ecosystem is None:
        return EcosystemConfidenceResult(
            "unknown", 0, "NONE", 0, 0,
            "ECOSYSTEM_NAME_NOT_AVAILABLE",
        )

    return score_ecosystem_confidence(ecosystem, markers)
