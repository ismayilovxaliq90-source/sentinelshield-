from __future__ import annotations

import os
import pwd
import grp
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping


class LeastPrivilegeError(ValueError):
    """Raised when least-privilege validation fails."""


@dataclass(frozen=True)
class PrivilegeIdentity:
    uid: int
    gid: int
    username: str = ""
    groupname: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.uid, bool) or not isinstance(self.uid, int):
            raise TypeError("uid must be int")

        if isinstance(self.gid, bool) or not isinstance(self.gid, int):
            raise TypeError("gid must be int")

        if self.uid < 0:
            raise ValueError("uid must be non-negative")

        if self.gid < 0:
            raise ValueError("gid must be non-negative")

        if not isinstance(self.username, str):
            raise TypeError("username must be str")

        if not isinstance(self.groupname, str):
            raise TypeError("groupname must be str")

    def to_dict(self) -> dict[str, object]:
        return {
            "uid": self.uid,
            "gid": self.gid,
            "username": self.username,
            "groupname": self.groupname,
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
            raise ValueError("minimum_uid must be non-negative")

        if self.minimum_gid < 0:
            raise ValueError("minimum_gid must be non-negative")


@dataclass(frozen=True)
class LeastPrivilegeResult:
    allowed: bool
    identity: PrivilegeIdentity
    policy: LeastPrivilegePolicy
    failures: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be bool")

        if not isinstance(self.identity, PrivilegeIdentity):
            raise TypeError("identity must be PrivilegeIdentity")

        if not isinstance(self.policy, LeastPrivilegePolicy):
            raise TypeError("policy must be LeastPrivilegePolicy")

        if not isinstance(self.failures, tuple):
            raise TypeError("failures must be tuple")

        object.__setattr__(
            self,
            "failures",
            tuple(str(item) for item in self.failures),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "identity": self.identity.to_dict(),
            "policy": {
                "allow_root": self.policy.allow_root,
                "minimum_uid": self.policy.minimum_uid,
                "minimum_gid": self.policy.minimum_gid,
            },
            "failures": list(self.failures),
        }

    @property
    def safe(self) -> bool:
        return self.allowed

    @property
    def reason(self) -> str | None:
        return self.failures[0] if self.failures else None


def _validate_identity(identity: PrivilegeIdentity) -> None:
    if not isinstance(identity, PrivilegeIdentity):
        raise TypeError("identity must be PrivilegeIdentity")


def get_current_identity(
    *,
    geteuid: Callable[[], int] | None = None,
    getegid: Callable[[], int] | None = None,
) -> PrivilegeIdentity:
    """
    Read the effective UID/GID without changing process privileges.

    Optional callables are provided intentionally so validation can be tested
    without modifying the real process identity.
    """

    uid_reader = os.geteuid if geteuid is None else geteuid
    gid_reader = os.getegid if getegid is None else getegid

    try:
        uid = uid_reader()
        gid = gid_reader()
    except Exception as exc:
        raise LeastPrivilegeError(
            "unable to determine effective process identity"
        ) from exc

    if isinstance(uid, bool) or not isinstance(uid, int):
        raise LeastPrivilegeError("effective UID must be int")

    if isinstance(gid, bool) or not isinstance(gid, int):
        raise LeastPrivilegeError("effective GID must be int")

    if uid < 0:
        raise LeastPrivilegeError("effective UID must be non-negative")

    if gid < 0:
        raise LeastPrivilegeError("effective GID must be non-negative")

    username = ""
    groupname = ""

    try:
        username = pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        username = ""

    try:
        groupname = grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        groupname = ""

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
    if policy is None:
        policy = LeastPrivilegePolicy()

    _validate_identity(identity)

    failures: list[str] = []

    if not policy.allow_root and identity.uid == 0:
        failures.append("ROOT_UID_NOT_ALLOWED")

    if identity.uid < policy.minimum_uid:
        failures.append("UID_BELOW_MINIMUM")

    if identity.gid < policy.minimum_gid:
        failures.append("GID_BELOW_MINIMUM")

    unique_failures = tuple(dict.fromkeys(failures))

    return LeastPrivilegeResult(
        allowed=not unique_failures,
        identity=identity,
        policy=policy,
        failures=unique_failures,
    )


def validate_current_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    if policy is None:
        policy = LeastPrivilegePolicy()

    identity = get_current_identity()

    return enforce_least_privilege(
        identity,
        policy,
    )


def require_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    result = validate_current_least_privilege(policy)

    if not result.allowed:
        raise LeastPrivilegeError(
            "least privilege validation failed: "
            + ", ".join(result.failures)
        )

    return result
