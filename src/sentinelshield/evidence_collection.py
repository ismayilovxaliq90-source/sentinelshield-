from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


class EvidenceCollectionError(RuntimeError):
    """Raised when evidence cannot be collected safely."""


@dataclass(frozen=True)
class EvidenceItem:
    name: str
    value: str
    digest: str


@dataclass(frozen=True)
class EvidenceBundle:
    execution_id: str
    items: tuple[EvidenceItem, ...]
    bundle_digest: str


class EvidenceCollector:
    """
    Task 38 — Evidence Collection.

    Collects structured execution evidence.
    Values are converted to safe strings and sensitive-looking
    values are redacted before the evidence bundle is created.
    """

    SECRET_WORDS = (
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "auth_token",
        "private_key",
    )

    def __init__(self) -> None:
        self._items: list[EvidenceItem] = []

    @staticmethod
    def _validate_execution_id(
        execution_id: str,
    ) -> str:
        if not isinstance(execution_id, str):
            raise TypeError(
                "execution_id must be a string"
            )

        execution_id = execution_id.strip()

        if not execution_id:
            raise ValueError(
                "execution_id cannot be empty"
            )

        return execution_id

    @classmethod
    def redact(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "value must be a string"
            )

        lowered = value.lower()

        for word in cls.SECRET_WORDS:
            if word in lowered:
                if "=" in value:
                    prefix = value.split("=", 1)[0]
                    return f"{prefix}=[REDACTED]"

                if ":" in value:
                    prefix = value.split(":", 1)[0]
                    return f"{prefix}=[REDACTED]"

                return "[REDACTED]"

        return value

    @staticmethod
    def digest(value: str) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "value must be a string"
            )

        return hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()

    def add(
        self,
        name: str,
        value: Any,
    ) -> EvidenceItem:
        if not isinstance(name, str):
            raise TypeError(
                "evidence name must be a string"
            )

        name = name.strip()

        if not name:
            raise ValueError(
                "evidence name cannot be empty"
            )

        safe_value = self.redact(
            str(value)
        )

        item = EvidenceItem(
            name=name,
            value=safe_value,
            digest=self.digest(safe_value),
        )

        self._items.append(item)

        return item

    def collect(
        self,
        execution_id: str,
        evidence: dict[str, Any],
    ) -> EvidenceBundle:
        execution_id = self._validate_execution_id(
            execution_id
        )

        if not isinstance(evidence, dict):
            raise TypeError(
                "evidence must be a dictionary"
            )

        self._items.clear()

        for name in sorted(evidence):
            self.add(
                name,
                evidence[name],
            )

        canonical = json.dumps(
            [
                {
                    "name": item.name,
                    "value": item.value,
                    "digest": item.digest,
                }
                for item in self._items
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        bundle_digest = self.digest(
            canonical
        )

        return EvidenceBundle(
            execution_id=execution_id,
            items=tuple(self._items),
            bundle_digest=bundle_digest,
        )

    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._items)

    def clear(self) -> None:
        self._items.clear()
