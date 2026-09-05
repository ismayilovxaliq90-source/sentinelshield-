from __future__ import annotations

import os
from dataclasses import dataclass


class PrivilegeViolation(PermissionError):
    """Raised when the current privilege policy is violated."""


@dataclass(frozen=True)
class PrivilegeState:
    uid: int
    euid: int
    gid: int
    egid: int
    is_root: bool
    elevated: bool


class LeastPrivilegeController:
    """
    Deterministic least-privilege policy controller.

    This controller does not grant privileges and does not change
    operating-system permissions. It only detects the current
    privilege state and enforces the configured execution policy.
    """

    def __init__(
        self,
        allow_root: bool = False,
        allow_elevated: bool = False,
    ) -> None:
        self.allow_root = allow_root
        self.allow_elevated = allow_elevated

    def inspect(self) -> PrivilegeState:
        uid = os.getuid()
        euid = os.geteuid()
        gid = os.getgid()
        egid = os.getegid()

        return PrivilegeState(
            uid=uid,
            euid=euid,
            gid=gid,
            egid=egid,
            is_root=(euid == 0),
            elevated=(euid != uid or egid != gid),
        )

    def validate(self) -> PrivilegeState:
        state = self.inspect()

        if state.is_root and not self.allow_root:
            raise PrivilegeViolation(
                "root execution is not allowed"
            )

        if state.elevated and not self.allow_elevated:
            raise PrivilegeViolation(
                "elevated execution is not allowed"
            )

        return state

    def is_allowed(self) -> bool:
        try:
            self.validate()
        except PrivilegeViolation:
            return False

        return True
