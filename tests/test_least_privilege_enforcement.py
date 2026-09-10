from __future__ import annotations

import pytest

from sentinelshield.least_privilege_enforcement import (
    LeastPrivilegeError,
    LeastPrivilegePolicy,
    LeastPrivilegeResult,
    PrivilegeIdentity,
    enforce_least_privilege,
    get_current_identity,
    require_least_privilege,
    validate_current_least_privilege,
)


def test_non_root_identity_is_allowed() -> None:
    identity = PrivilegeIdentity(
        uid=1000,
        gid=1000,
        username="runner",
        groupname="runner",
    )

    result = enforce_least_privilege(identity)

    assert result.allowed is True
    assert result.failures == ()
    assert result.identity == identity


def test_root_identity_is_rejected_by_default() -> None:
    identity = PrivilegeIdentity(
        uid=0,
        gid=0,
        username="root",
        groupname="root",
    )

    result = enforce_least_privilege(identity)

    assert result.allowed is False
    assert "ROOT_UID_NOT_ALLOWED" in result.failures


def test_root_can_be_explicitly_allowed() -> None:
    identity = PrivilegeIdentity(
        uid=0,
        gid=0,
        username="root",
        groupname="root",
    )

    policy = LeastPrivilegePolicy(
        allow_root=True,
        minimum_uid=0,
    )

    result = enforce_least_privilege(identity, policy)

    assert result.allowed is True
    assert result.failures == ()


def test_minimum_uid_is_enforced() -> None:
    identity = PrivilegeIdentity(
        uid=10,
        gid=10,
    )

    policy = LeastPrivilegePolicy(
        minimum_uid=100,
        minimum_gid=0,
    )

    result = enforce_least_privilege(identity, policy)

    assert result.allowed is False
    assert "UID_BELOW_MINIMUM" in result.failures


def test_minimum_gid_is_enforced() -> None:
    identity = PrivilegeIdentity(
        uid=1000,
        gid=10,
    )

    policy = LeastPrivilegePolicy(
        minimum_uid=1,
        minimum_gid=100,
    )

    result = enforce_least_privilege(identity, policy)

    assert result.allowed is False
    assert "GID_BELOW_MINIMUM" in result.failures


def test_invalid_identity_type_is_rejected() -> None:
    with pytest.raises(TypeError):
        enforce_least_privilege(object())


def test_policy_rejects_boolean_minimum_uid() -> None:
    with pytest.raises(TypeError):
        LeastPrivilegePolicy(minimum_uid=True)


def test_policy_rejects_boolean_minimum_gid() -> None:
    with pytest.raises(TypeError):
        LeastPrivilegePolicy(minimum_gid=False)


def test_policy_rejects_invalid_allow_root_type() -> None:
    with pytest.raises(TypeError):
        LeastPrivilegePolicy(allow_root=1)


def test_policy_rejects_negative_minimum_uid() -> None:
    with pytest.raises(ValueError):
        LeastPrivilegePolicy(minimum_uid=-1)


def test_policy_rejects_negative_minimum_gid() -> None:
    with pytest.raises(ValueError):
        LeastPrivilegePolicy(minimum_gid=-1)


def test_get_current_identity_uses_effective_ids() -> None:
    identity = get_current_identity(
        geteuid=lambda: 1000,
        getegid=lambda: 1001,
    )

    assert identity.uid == 1000
    assert identity.gid == 1001


def test_get_current_identity_rejects_invalid_uid() -> None:
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: -1,
            getegid=lambda: 1000,
        )


def test_get_current_identity_rejects_invalid_gid() -> None:
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: 1000,
            getegid=lambda: -1,
        )


def test_get_current_identity_rejects_boolean_uid() -> None:
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: True,
            getegid=lambda: 1000,
        )


def test_get_current_identity_rejects_boolean_gid() -> None:
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: 1000,
            getegid=lambda: False,
        )


def test_get_current_identity_failure_is_wrapped() -> None:
    def broken_uid():
        raise OSError("identity unavailable")

    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=broken_uid,
            getegid=lambda: 1000,
        )


def test_privilege_identity_rejects_boolean_uid() -> None:
    with pytest.raises(TypeError):
        PrivilegeIdentity(uid=True, gid=1000)


def test_privilege_identity_rejects_boolean_gid() -> None:
    with pytest.raises(TypeError):
        PrivilegeIdentity(uid=1000, gid=False)


def test_result_to_dict_is_serializable() -> None:
    identity = PrivilegeIdentity(
        uid=1000,
        gid=1000,
        username="runner",
        groupname="runner",
    )

    result = enforce_least_privilege(identity)

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["allowed"] is True
    assert data["identity"]["uid"] == 1000
    assert data["identity"]["gid"] == 1000
    assert data["identity"]["username"] == "runner"
    assert data["identity"]["groupname"] == "runner"
    assert data["failures"] == []


def test_result_is_frozen() -> None:
    identity = PrivilegeIdentity(
        uid=1000,
        gid=1000,
    )

    result = enforce_least_privilege(identity)

    with pytest.raises(AttributeError):
        result.allowed = False


def test_failures_are_tuple() -> None:
    identity = PrivilegeIdentity(
        uid=1000,
        gid=1000,
    )

    result = enforce_least_privilege(identity)

    assert isinstance(result.failures, tuple)


def test_current_runner_should_satisfy_least_privilege() -> None:
    result = validate_current_least_privilege()

    assert result.identity is not None
    assert result.allowed is True
    assert result.identity.uid > 0


def test_require_least_privilege_returns_valid_result() -> None:
    result = require_least_privilege()

    assert isinstance(result, LeastPrivilegeResult)
    assert result.allowed is True
    assert result.identity is not None
    assert result.identity.uid > 0


def test_require_least_privilege_rejects_root_policy() -> None:
    identity = PrivilegeIdentity(
        uid=0,
        gid=0,
        username="root",
        groupname="root",
    )

    result = enforce_least_privilege(identity)

    assert result.allowed is False

    with pytest.raises(LeastPrivilegeError):
        if not result.allowed:
            raise LeastPrivilegeError(
                "least privilege validation failed"
            )
