from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass(frozen=True)
class CWE:
    identifier: str
    cwe: str


@dataclass(frozen=True)
class CWEExtractionResult:
    cwes: tuple[CWE, ...]
    extracted: bool
    status: str


_CWE_FIELDS = (
    "cwe",
    "cwe_id",
    "cwe_ids",
    "weakness",
    "weaknesses",
)

_IDENTIFIER_FIELDS = (
    "identifier",
    "id",
    "vulnerability_id",
    "vuln_id",
    "cve",
    "ghsa",
)

_CWE_PATTERN = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


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


def _normalize_cwe(value: Any) -> str | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        if value <= 0:
            return None
        return f"CWE-{value}"

    if not isinstance(value, str):
        return None

    normalized = value.strip().upper()

    if not normalized:
        return None

    if normalized.isdigit():
        number = int(normalized)
        if number <= 0:
            return None
        return f"CWE-{number}"

    match = _CWE_PATTERN.fullmatch(normalized)

    if match is None:
        return None

    number = int(match.group(1))

    if number <= 0:
        return None

    return f"CWE-{number}"


def _flatten_cwe_values(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()

    if isinstance(value, (list, tuple, set, frozenset)):
        flattened: list[Any] = []

        for item in value:
            if isinstance(item, (list, tuple, set, frozenset)):
                flattened.extend(_flatten_cwe_values(item))
            else:
                flattened.append(item)

        return tuple(flattened)

    return (value,)


def _extract_single(vulnerability: Any) -> tuple[CWE, ...]:
    identifier_value = _read_field(
        vulnerability,
        _IDENTIFIER_FIELDS,
    )

    identifier = _normalize_identifier(identifier_value)

    if identifier is None:
        raise ValueError("INVALID_VULNERABILITY_IDENTIFIER")

    cwe_value = _read_field(
        vulnerability,
        _CWE_FIELDS,
    )

    values = _flatten_cwe_values(cwe_value)

    if not values:
        return ()

    normalized: set[str] = set()

    for value in values:
        # Support common dictionary weakness objects:
        # {"id": "CWE-79"} or {"cwe_id": "CWE-79"}
        if isinstance(value, dict):
            nested = _read_field(
                value,
                ("id", "cwe", "cwe_id", "identifier"),
            )

            if nested is None:
                raise ValueError("INVALID_CWE")

            value = nested

        normalized_cwe = _normalize_cwe(value)

        if normalized_cwe is None:
            raise ValueError("INVALID_CWE")

        normalized.add(normalized_cwe)

    return tuple(
        CWE(identifier=identifier, cwe=cwe)
        for cwe in sorted(normalized)
    )


def extract_cwes(
    vulnerabilities: Any,
) -> CWEExtractionResult:
    if vulnerabilities is None:
        return CWEExtractionResult(
            cwes=(),
            extracted=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(vulnerabilities, (str, bytes, bytearray)):
        return CWEExtractionResult(
            cwes=(),
            extracted=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    if isinstance(vulnerabilities, dict):
        collection = (vulnerabilities,)
    else:
        try:
            collection = tuple(vulnerabilities)
        except TypeError:
            return CWEExtractionResult(
                cwes=(),
                extracted=False,
                status="UNSUPPORTED_VULNERABILITY_COLLECTION",
            )

    if not collection:
        return CWEExtractionResult(
            cwes=(),
            extracted=False,
            status="NO_VULNERABILITIES",
        )

    extracted: set[CWE] = set()

    for vulnerability in collection:
        try:
            items = _extract_single(vulnerability)
        except ValueError as error:
            return CWEExtractionResult(
                cwes=(),
                extracted=False,
                status=str(error),
            )

        extracted.update(items)

    if not extracted:
        return CWEExtractionResult(
            cwes=(),
            extracted=False,
            status="NO_CWE",
        )

    ordered = tuple(
        sorted(
            extracted,
            key=lambda item: (
                item.identifier,
                item.cwe,
            ),
        )
    )

    return CWEExtractionResult(
        cwes=ordered,
        extracted=True,
        status="CWE_EXTRACTED",
    )


def extract_cwe(
    vulnerability: Any,
) -> CWEExtractionResult:
    return extract_cwes((vulnerability,))
