from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SymlinkPolicyResult:
    valid: bool
    path: Path | None
    is_symlink: bool
    reason: str


class SymlinkPolicy:
    """
    Applies the SentinelShield project-root symlink policy.

    Default policy: a symlink cannot be accepted as the project root.

    This check is read-only and does not follow the symlink target.
    """

    def validate(
        self,
        value: Any,
    ) -> SymlinkPolicyResult:

        if value is None:
            return SymlinkPolicyResult(
                valid=False,
                path=None,
                is_symlink=False,
                reason="PATH_IS_NONE",
            )

        if not isinstance(value, (str, Path)):
            return SymlinkPolicyResult(
                valid=False,
                path=None,
                is_symlink=False,
                reason="UNSUPPORTED_PATH_TYPE",
            )

        if isinstance(value, str):
            value = value.strip()

            if not value:
                return SymlinkPolicyResult(
                    valid=False,
                    path=None,
                    is_symlink=False,
                    reason="PATH_IS_EMPTY",
                )

        path = Path(value).expanduser()

        if "\x00" in str(path):
            return SymlinkPolicyResult(
                valid=False,
                path=None,
                is_symlink=False,
                reason="NULL_CHARACTER_NOT_ALLOWED",
            )

        try:
            if path.is_symlink():
                return SymlinkPolicyResult(
                    valid=False,
                    path=path,
                    is_symlink=True,
                    reason="SYMLINK_NOT_ALLOWED",
                )

            if not path.exists():
                return SymlinkPolicyResult(
                    valid=False,
                    path=path,
                    is_symlink=False,
                    reason="PATH_NOT_FOUND",
                )

            if not path.is_dir():
                return SymlinkPolicyResult(
                    valid=False,
                    path=path,
                    is_symlink=False,
                    reason="PATH_IS_NOT_DIRECTORY",
                )

        except PermissionError:
            return SymlinkPolicyResult(
                valid=False,
                path=path,
                is_symlink=False,
                reason="FILESYSTEM_PERMISSION_DENIED",
            )

        except OSError:
            return SymlinkPolicyResult(
                valid=False,
                path=path,
                is_symlink=False,
                reason="FILESYSTEM_OS_ERROR",
            )

        return SymlinkPolicyResult(
            valid=True,
            path=path,
            is_symlink=False,
            reason="SYMLINK_POLICY_ACCEPTED",
        )


def validate_symlink_policy(
    value: Any,
) -> SymlinkPolicyResult:
    return SymlinkPolicy().validate(value)
