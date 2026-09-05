from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class DiskLogProtectionError(RuntimeError):
    """Raised when disk or log growth violates SentinelShield policy."""


@dataclass(frozen=True)
class SizeCheck:
    path: str
    size_bytes: int
    limit_bytes: int
    allowed: bool


class DiskLogRunawayProtection:
    """
    Deterministic protection against excessive disk/log growth.

    This component only observes file sizes.
    It does not delete, truncate, modify, or create files.
    """

    DEFAULT_FILE_LIMIT = 100 * 1024 * 1024
    DEFAULT_LOG_LIMIT = 50 * 1024 * 1024

    def __init__(
        self,
        file_limit_bytes: int = DEFAULT_FILE_LIMIT,
        log_limit_bytes: int = DEFAULT_LOG_LIMIT,
    ) -> None:

        self._validate_limit(
            file_limit_bytes,
            "file_limit_bytes",
        )

        self._validate_limit(
            log_limit_bytes,
            "log_limit_bytes",
        )

        self.file_limit_bytes = file_limit_bytes
        self.log_limit_bytes = log_limit_bytes

    @staticmethod
    def _validate_limit(
        value: int,
        name: str,
    ) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(
                f"{name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{name} must be greater than zero"
            )

    @staticmethod
    def size_bytes(path: str | Path) -> int:
        target = Path(path)

        try:
            return target.stat().st_size
        except OSError as exc:
            raise DiskLogProtectionError(
                f"unable to read file size: {target}"
            ) from exc

    def check_file(
        self,
        path: str | Path,
    ) -> SizeCheck:
        size = self.size_bytes(path)

        allowed = size <= self.file_limit_bytes

        return SizeCheck(
            path=str(path),
            size_bytes=size,
            limit_bytes=self.file_limit_bytes,
            allowed=allowed,
        )

    def check_log(
        self,
        path: str | Path,
    ) -> SizeCheck:
        size = self.size_bytes(path)

        allowed = size <= self.log_limit_bytes

        return SizeCheck(
            path=str(path),
            size_bytes=size,
            limit_bytes=self.log_limit_bytes,
            allowed=allowed,
        )

    def require_file_safe(
        self,
        path: str | Path,
    ) -> SizeCheck:
        result = self.check_file(path)

        if not result.allowed:
            raise DiskLogProtectionError(
                f"file size limit exceeded: "
                f"{result.size_bytes} > "
                f"{result.limit_bytes}"
            )

        return result

    def require_log_safe(
        self,
        path: str | Path,
    ) -> SizeCheck:
        result = self.check_log(path)

        if not result.allowed:
            raise DiskLogProtectionError(
                f"log size limit exceeded: "
                f"{result.size_bytes} > "
                f"{result.limit_bytes}"
            )

        return result

    def is_file_safe(
        self,
        path: str | Path,
    ) -> bool:
        try:
            self.require_file_safe(path)
        except DiskLogProtectionError:
            return False

        return True

    def is_log_safe(
        self,
        path: str | Path,
    ) -> bool:
        try:
            self.require_log_safe(path)
        except DiskLogProtectionError:
            return False

        return True
