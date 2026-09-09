from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class OSVAdvisory:
    advisory_id: str
    summary: str | None
    details: str | None
    aliases: tuple[str, ...]
    modified: str | None
    published: str | None
    withdrawn: str | None
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class OSVIngestionResult:
    advisories: tuple[OSVAdvisory, ...]
    ingested: bool
    status: str


def _as_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _extract_aliases(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()

    aliases: list[str] = []

    for item in value:
        if isinstance(item, str):
            item = item.strip()
            if item and item not in aliases:
                aliases.append(item)

    return tuple(aliases)


def _parse_advisory(value: Any) -> tuple[OSVAdvisory | None, str]:
    if not isinstance(value, Mapping):
        return None, "INVALID_ADVISORY"

    advisory_id = _as_string(value.get("id"))

    if advisory_id is None:
        return None, "ADVISORY_ID_MISSING"

    summary = _as_string(value.get("summary"))
    details = _as_string(value.get("details"))
    modified = _as_string(value.get("modified"))
    published = _as_string(value.get("published"))
    withdrawn = _as_string(value.get("withdrawn"))
    aliases = _extract_aliases(value.get("aliases"))

    raw = dict(value)

    return (
        OSVAdvisory(
            advisory_id=advisory_id,
            summary=summary,
            details=details,
            aliases=aliases,
            modified=modified,
            published=published,
            withdrawn=withdrawn,
            raw=raw,
        ),
        "VALID",
    )


def ingest_osv_response(
    payload: Any,
) -> OSVIngestionResult:
    """
    Parse an already retrieved OSV JSON response.

    Read-only ingestion operation.

    Does not:
      - install packages
      - modify project files
      - execute project code
      - modify manifests
      - modify lockfiles
      - perform remediation
    """

    if payload is None:
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="PAYLOAD_IS_NONE",
        )

    if isinstance(payload, (str, bytes, bytearray)):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            return OSVIngestionResult(
                advisories=(),
                ingested=False,
                status="INVALID_JSON",
            )

    if not isinstance(payload, Mapping):
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="INVALID_OSV_RESPONSE",
        )

    advisory_values: list[Any] = []

    if "vulns" in payload:
        vulns = payload["vulns"]

        if vulns is None:
            return OSVIngestionResult(
                advisories=(),
                ingested=True,
                status="NO_ADVISORIES",
            )

        if not isinstance(vulns, (list, tuple)):
            return OSVIngestionResult(
                advisories=(),
                ingested=False,
                status="INVALID_VULNS_COLLECTION",
            )

        advisory_values.extend(vulns)

    elif "id" in payload:
        advisory_values.append(payload)

    else:
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="OSV_ADVISORIES_NOT_FOUND",
        )

    advisories: list[OSVAdvisory] = []

    for value in advisory_values:
        advisory, status = _parse_advisory(value)

        if advisory is None:
            return OSVIngestionResult(
                advisories=(),
                ingested=False,
                status=status,
            )

        advisories.append(advisory)

    advisories.sort(
        key=lambda advisory: (
            advisory.advisory_id.casefold(),
            advisory.advisory_id,
        )
    )

    if not advisories:
        return OSVIngestionResult(
            advisories=(),
            ingested=True,
            status="NO_ADVISORIES",
        )

    return OSVIngestionResult(
        advisories=tuple(advisories),
        ingested=True,
        status="OSV_INGESTED",
    )


def ingest_osv_json(
    payload: str | bytes | bytearray,
) -> OSVIngestionResult:
    return ingest_osv_response(payload)


def fetch_osv_advisories(
    package: str,
    ecosystem: str | None = None,
    *,
    timeout: float = 10.0,
    api_url: str = OSV_API_URL,
) -> OSVIngestionResult:
    """
    Read-only network ingestion from OSV.

    No local filesystem or project state is modified.
    """

    if not isinstance(package, str) or not package.strip():
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="PACKAGE_IS_INVALID",
        )

    if ecosystem is not None:
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            return OSVIngestionResult(
                advisories=(),
                ingested=False,
                status="ECOSYSTEM_IS_INVALID",
            )

    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="INVALID_TIMEOUT",
        )

    query: dict[str, Any] = {
        "package": {
            "name": package.strip(),
        }
    }

    if ecosystem is not None:
        query["package"]["ecosystem"] = ecosystem.strip()

    body = json.dumps(query).encode("utf-8")

    request = Request(
        api_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "SentinelShield-OSV-Ingestion",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=float(timeout)) as response:
            response_body = response.read()

    except HTTPError as error:
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status=f"OSV_HTTP_ERROR_{error.code}",
        )

    except (URLError, TimeoutError):
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="OSV_NETWORK_ERROR",
        )

    except OSError:
        return OSVIngestionResult(
            advisories=(),
            ingested=False,
            status="OSV_NETWORK_ERROR",
        )

    return ingest_osv_json(response_body)
