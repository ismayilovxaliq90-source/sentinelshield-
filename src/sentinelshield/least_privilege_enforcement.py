from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional


class LeastPrivilegeError(ValueError):
    """Raised when privilege information is invalid."""


@dataclass(frozen=True)
class PrivilegeIdentity:
    uid: int
    gid: int
    username: Optional[str] = None
    groupname: Optional[str] = None

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "gid": self.gid,
            "username": self.username,
            "groupname": self.groupname,
            "is_root": self.is_root,
        }


@dataclass(frozen=True)
class LeastPrivilegePolicy:
    allow_root: bool = False
    minimum_uid: int = 1
    minimum_gid: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.allow_root, bool):
            raise TypeError("allow_root must be bool")

        if isinstance(self.minimum_uid, bool) or not isinstance(
            self.minimum_uid, int
        ):
            raise TypeError("minimum_uid must be int")

        if isinstance(self.minimum_gid, bool) or not isinstance(
            self.minimum_gid, int
        ):
            raise TypeError("minimum_gid must be int")

        if self.minimum_uid < 0:
            raise LeastPrivilegeError("minimum_uid cannot be negative")

        if self.minimum_gid < 0:
            raise LeastPrivilegeError("minimum_gid cannot be negative")


@dataclass(frozen=True)
class LeastPrivilegeResult:
    allowed: bool
    identity: Optional[PrivilegeIdentity]
    reason: str
    policy: LeastPrivilegePolicy

    @property
    def uid(self) -> Optional[int]:
        return None if self.identity is None else self.identity.uid

    @property
    def gid(self) -> Optional[int]:
        return None if self.identity is None else self.identity.gid

    @property
    def is_root(self) -> bool:
        return bool(self.identity and self.identity.is_root)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "identity": (
                None if self.identity is None else self.identity.to_dict()
            ),
            "reason": self.reason,
            "policy": {
                "allow_root": self.policy.allow_root,
                "minimum_uid": self.policy.minimum_uid,
                "minimum_gid": self.policy.minimum_gid,
            },
        }


def _validate_numeric_identity(uid: int, gid: int) -> None:
    if isinstance(uid, bool) or not isinstance(uid, int):
        raise LeastPrivilegeError("uid must be int")

    if isinstance(gid, bool) or not isinstance(gid, int):
        raise LeastPrivilegeError("gid must be int")

    if uid < 0:
        raise LeastPrivilegeError("uid cannot be negative")

    if gid < 0:
        raise LeastPrivilegeError("gid cannot be negative")


def get_current_identity(
    geteuid: Optional[Callable[[], int]] = None,
    getegid: Optional[Callable[[], int]] = None,
) -> PrivilegeIdentity:
    """
    Read the current effective UID/GID.

    This function is intentionally read-only:
    it never changes UID, GID, groups, capabilities, or process privileges.
    """
    uid_reader = geteuid or getattr(os, "geteuid", None)
    gid_reader = getegid or getattr(os, "getegid", None)

    if uid_reader is None:
        raise LeastPrivilegeError("effective UID is unavailable")

    if gid_reader is None:
        raise LeastPrivilegeError("effective GID is unavailable")

    try:
        uid = uid_reader()
        gid = gid_reader()
    except (OSError, AttributeError, TypeError) as exc:
        raise LeastPrivilegeError(
            "unable to determine effective UID/GID"
        ) from exc

    _validate_numeric_identity(uid, gid)

    username: Optional[str] = None
    groupname: Optional[str] = None

    try:
        import pwd

        username = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, OSError):
        username = None

    try:
        import grp

        groupname = grp.getgrgid(gid).gr_name
    except (ImportError, KeyError, OSError):
        groupname = None

    return PrivilegeIdentity(
        uid=uid,
        gid=gid,
        username=username,
        groupname=groupname,
    )


def enforce_least_privilege(
    identity: PrivilegeIdentity,
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    """
    Validate whether an execution identity satisfies the least-privilege policy.

    No privilege changes are performed.
    """
    active_policy = policy or LeastPrivilegePolicy()

    if not isinstance(identity, PrivilegeIdentity):
        raise TypeError("identity must be PrivilegeIdentity")

    _validate_numeric_identity(identity.uid, identity.gid)

    if identity.uid < active_policy.minimum_uid:
        return LeastPrivilegeResult(
            allowed=False,
            identity=identity,
            reason="UID_BELOW_MINIMUM",
            policy=active_policy,
        )

    if identity.gid < active_policy.minimum_gid:
        return LeastPrivilegeResult(
            allowed=False,
            identity=identity,
            reason="GID_BELOW_MINIMUM",
            policy=active_policy,
        )

    if identity.is_root and not active_policy.allow_root:
        return LeastPrivilegeResult(
            allowed=False,
            identity=identity,
            reason="ROOT_PRIVILEGE_FORBIDDEN",
            policy=active_policy,
        )

    return LeastPrivilegeResult(
        allowed=True,
        identity=identity,
        reason="LEAST_PRIVILEGE_SATISFIED",
        policy=active_policy,
    )


def validate_current_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    """
    Validate the current process privilege level.

    This performs observation only and never escalates or changes privilege.
    """
    active_policy = policy or LeastPrivilegePolicy()

    try:
        identity = get_current_identity()
    except LeastPrivilegeError as exc:
        return LeastPrivilegeResult(
            allowed=False,
            identity=None,
            reason=f"IDENTITY_VALIDATION_FAILED:{exc}",
            policy=active_policy,
        )

    return enforce_least_privilege(identity, active_policy)


def require_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    """
    Enforce the policy by refusing to continue when validation fails.

    No privilege escalation or privilege mutation is attempted.
    """
    result = validate_current_least_privilege(policy)

    if not result.allowed:
        raise LeastPrivilegeError(result.reason)

    return result
