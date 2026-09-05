from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


class DeterministicValidationError(ValueError):
    """Raised when deterministic validation cannot be performed safely."""


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    digest: str
    reason: str


class DeterministicValidator:
    """
    Task 35 — Deterministic Validation.

    Produces stable validation results for equivalent structured input.
    """

    def validate(
        self,
        data: Any,
        *,
        expected_digest: str | None = None,
    ) -> ValidationResult:

        serialized = self.canonicalize(data)
        digest = self.digest(serialized)

        valid = True
        reason = "validation passed"

        if expected_digest is not None:
            if not isinstance(expected_digest, str):
                raise TypeError(
                    "expected_digest must be a string"
                )

            valid = digest == expected_digest

            if not valid:
                reason = "digest mismatch"

        return ValidationResult(
            valid=valid,
            digest=digest,
            reason=reason,
        )

    @staticmethod
    def canonicalize(data: Any) -> str:
        try:
            return json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise DeterministicValidationError(
                f"data cannot be deterministically serialized: {exc}"
            ) from exc

    @staticmethod
    def digest(canonical_data: str) -> str:
        if not isinstance(canonical_data, str):
            raise TypeError(
                "canonical_data must be a string"
            )

        return hashlib.sha256(
            canonical_data.encode("utf-8")
        ).hexdigest()

    def matches(
        self,
        data: Any,
        expected_digest: str,
    ) -> bool:
        result = self.validate(
            data,
            expected_digest=expected_digest,
        )

        return result.valid
