from __future__ import annotations

import os
from dataclasses import dataclass


class LeastPrivilegeError(ValueError):
    """Raised when least-privilege inputs are invalid."""


@dataclass(frozen=True)
class PrivilegeIdentity:
    uid: int
    gid: int


@dataclass(frozen=True)
class LeastPrivilegePolicy:
    allow_root: bool = False
    minimum_uid: int = 1
    minimum_gid: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.allow_root, bool) is False:
            raise LeastPrivilegeError("allow_root must be bool")

        if isinstance(self.minimum_uid, bool) or not isinstance(
            self.minimum_uid, int
        ):
            raise LeastPrivilegeError("minimum_uid must be int")

        if isinstance(self.minimum_gid, bool) or not isinstance(
            self.minimum_gid, int
        ):
            raise LeastPrivilegeError("minimum_gid must be int")

        if self.minimum_uid < 0:
            raise LeastPrivilegeError("minimum_uid must be >= 0")

        if self.minimum_gid < 0:
            raise LeastPrivilegeError("minimum_gid must be >= 0")


@dataclass(frozen=True)
class LeastPrivilegeResult:
    allowed: bool
    is_root: bool
    uid: int
    gid: int
    reason: str


def _validate_identity(identity: PrivilegeIdentity) -> None:
    if not isinstance(identity, PrivilegeIdentity):
        raise LeastPrivilegeError("identity must be PrivilegeIdentity")

    if isinstance(identity.uid, bool) or not isinstance(identity.uid, int):
        raise LeastPrivilegeError("uid must be int")

    if isinstance(identity.gid, bool) or not isinstance(identity.gid, int):
        raise LeastPrivilegeError("gid must be int")

    if identity.uid < 0:
        raise LeastPrivilegeError("uid must be >= 0")

    if identity.gid < 0:
        raise LeastPrivilegeError("gid must be >= 0")


def enforce_least_privilege(
    identity: PrivilegeIdentity,
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    if policy is None:
        policy = LeastPrivilegePolicy()

    if not isinstance(policy, LeastPrivilegePolicy):
        raise LeastPrivilegeError("policy must be LeastPrivilegePolicy")

    _validate_identity(identity)

    is_root = identity.uid == 0

    # Root is a security-special case and must be evaluated first.
    # This guarantees the canonical reason required by the policy.
    if is_root and not policy.allow_root:
        return LeastPrivilegeResult(
            allowed=False,
            is_root=True,
            uid=identity.uid,
            gid=identity.gid,
            reason="ROOT_PRIVILEGE_FORBIDDEN",
        )

    if identity.uid < policy.minimum_uid:
        return LeastPrivilegeResult(
            allowed=False,
            is_root=is_root,
            uid=identity.uid,
            gid=identity.gid,
            reason="UID_BELOW_MINIMUM",
        )

    if identity.gid < policy.minimum_gid:
        return LeastPrivilegeResult(
            allowed=False,
            is_root=is_root,
            uid=identity.uid,
            gid=identity.gid,
            reason="GID_BELOW_MINIMUM",
        )

    return LeastPrivilegeResult(
        allowed=True,
        is_root=is_root,
        uid=identity.uid,
        gid=identity.gid,
        reason="LEAST_PRIVILEGE_SATISFIED",
    )


def get_current_identity() -> PrivilegeIdentity:
    try:
        uid = os.getuid()
        gid = os.getgid()
    except OSError as error:
        raise LeastPrivilegeError(
            "Unable to determine current process identity"
        ) from error

    return PrivilegeIdentity(uid=uid, gid=gid)


def validate_current_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    identity = get_current_identity()
    return enforce_least_privilege(identity, policy)


def require_least_privilege(
    policy: LeastPrivilegePolicy | None = None,
) -> LeastPrivilegeResult:
    result = validate_current_least_privilege(policy)

    if not result.allowed:
        raise LeastPrivilegeError(result.reason)

    return result
