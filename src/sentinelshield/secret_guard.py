from __future__ import annotations

import re
from dataclasses import dataclass


class SecretExposureError(ValueError):
    """Raised when sensitive information is detected in protected data."""


@dataclass(frozen=True)
class SecretScanResult:
    safe: bool
    matches: tuple[str, ...]


class SecretExposureGuard:
    """
    Detects common secret patterns before data reaches execution or logging.

    The guard never returns the original secret value.
    Detected values are represented only by redacted markers.
    """

    SECRET_PATTERNS = (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)\s*[:=]\s*[^\s,;]+"
        ),
        re.compile(
            r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"
        ),
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
        ),
    )

    SENSITIVE_NAMES = frozenset(
        {
            "PASSWORD",
            "PASSWD",
            "SECRET",
            "SECRET_KEY",
            "API_KEY",
            "APIKEY",
            "ACCESS_TOKEN",
            "AUTH_TOKEN",
            "TOKEN",
            "PRIVATE_KEY",
        }
    )

    def scan(self, value: str) -> SecretScanResult:
        if not isinstance(value, str):
            raise TypeError("value must be a string")

        matches: list[str] = []

        for pattern in self.SECRET_PATTERNS:
            if pattern.search(value):
                matches.append("SECRET_PATTERN_DETECTED")

        return SecretScanResult(
            safe=not matches,
            matches=tuple(matches),
        )

    def validate(self, value: str) -> str:
        result = self.scan(value)

        if not result.safe:
            raise SecretExposureError(
                "secret exposure detected"
            )

        return value

    def redact(self, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")

        redacted = value

        for pattern in self.SECRET_PATTERNS:
            redacted = pattern.sub(
                lambda match: self._redaction(match.group(0)),
                redacted,
            )

        return redacted

    def validate_environment(
        self,
        environment: dict[str, str],
    ) -> None:
        if not isinstance(environment, dict):
            raise TypeError("environment must be a dictionary")

        for name, value in environment.items():
            if not isinstance(name, str):
                raise TypeError("environment variable name must be a string")

            if not isinstance(value, str):
                raise TypeError(
                    f"environment variable value must be a string: {name}"
                )

            if name.upper() in self.SENSITIVE_NAMES:
                raise SecretExposureError(
                    f"sensitive environment variable is not allowed: {name}"
                )

            self.validate(value)

    @staticmethod
    def _redaction(value: str) -> str:
        if ":" in value:
            prefix = value.split(":", 1)[0]
            return f"{prefix}: [REDACTED]"

        if "=" in value:
            prefix = value.split("=", 1)[0]
            return f"{prefix}=[REDACTED]"

        if value.lower().startswith("bearer "):
            return "Bearer [REDACTED]"

        if value.startswith("-----BEGIN"):
            return "[REDACTED PRIVATE KEY]"

        if value.startswith("AKIA"):
            return "[REDACTED ACCESS KEY]"

        return "[REDACTED]"
