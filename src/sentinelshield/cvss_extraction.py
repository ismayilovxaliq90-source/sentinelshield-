from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CVSS:
    identifier: str
    score: float


@dataclass(frozen=True)
class CVSSExtractionResult:
    cvss: tuple[CVSS, ...]
    extracted: bool
    status: str


_CVSS_FIELDS = (
    "cvss",
    "cvss_score",
    "cvss_v3_score",
    "cvss_v2_score",
    "score",
)

_IDENTIFIER_FIELDS = (
    "identifier",
    "id",
    "vulnerability_id",
    "vuln_id",
    "cve",
    "ghsa",
)


def _read_field(value: Any, fields: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for field in fields:
            if field in value:
                return value[field]
        return None

    for field in fields:
        try:
            result = getattr(value, field)
        except AttributeError:
            continue

        if result is not None:
            return result

    return None


def _normalize_identifier(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    return normalized


def _normalize_score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, str):
        normalized = value.strip()

        if not normalized:
            return None

        try:
            score = float(normalized)
        except ValueError:
            return None
    elif isinstance(value, (int, float)):
        score = float(value)
    else:
        return None

    if not 0.0 <= score <= 10.0:
        return None

    return round(score, 1)


def _extract_single(vulnerability: Any) -> CVSS:
    identifier_value = _read_field(
        vulnerability,
        _IDENTIFIER_FIELDS,
    )

    identifier = _normalize_identifier(identifier_value)

    if identifier is None:
        raise ValueError("INVALID_VULNERABILITY_IDENTIFIER")

    score_value = _read_field(
        vulnerability,
        _CVSS_FIELDS,
    )

    score = _normalize_score(score_value)

    if score is None:
        raise ValueError("INVALID_CVSS")

    return CVSS(
        identifier=identifier,
        score=score,
    )


def extract_cvss(
    vulnerabilities: Any,
) -> CVSSExtractionResult:
    if vulnerabilities is None:
        return CVSSExtractionResult(
            cvss=(),
            extracted=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(vulnerabilities, (str, bytes, bytearray)):
        return CVSSExtractionResult(
            cvss=(),
            extracted=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if isinstance(vulnerabilities, dict):
        collection = (vulnerabilities,)
    else:
        try:
            collection = tuple(vulnerabilities)
        except TypeError:
            return CVSSExtractionResult(
                cvss=(),
                extracted=False,
                status="UNSUPPORTED_VULNERABILITY_COLLECTION",
            )

    if not collection:
        return CVSSExtractionResult(
            cvss=(),
            extracted=False,
            status="NO_VULNERABILITIES",
        )

    extracted: set[CVSS] = set()

    for vulnerability in collection:
        try:
            item = _extract_single(vulnerability)
        except ValueError as error:
            return CVSSExtractionResult(
                cvss=(),
                extracted=False,
                status=str(error),
            )

        extracted.add(item)

    if not extracted:
        return CVSSExtractionResult(
            cvss=(),
            extracted=False,
            status="NO_CVSS",
        )

    ordered = tuple(
        sorted(
            extracted,
            key=lambda item: (
                item.identifier,
                item.score,
            ),
        )
    )

    return CVSSExtractionResult(
        cvss=ordered,
        extracted=True,
        status="CVSS_EXTRACTED",
    )


def extract_single_cvss(
    vulnerability: Any,
) -> CVSSExtractionResult:
    return extract_cvss((vulnerability,))
