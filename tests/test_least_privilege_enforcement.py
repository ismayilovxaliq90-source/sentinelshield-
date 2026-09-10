from __future__ import annotations

import pytest

from sentinelshield.least_privilege_enforcement import (
    LeastPrivilegeError,
    LeastPrivilegePolicy,
    PrivilegeIdentity,
    enforce_least_privilege,
    get_current_identity,
    require_least_privilege,
    validate_current_least_privilege,
)


def test_non_root_identity_is_allowed():
    identity = PrivilegeIdentity(uid=1000, gid=1000)

    result = enforce_least_privilege(identity)

    assert result.allowed is True
    assert result.is_root is False
    assert result.reason == "LEAST_PRIVILEGE_SATISFIED"


def test_root_identity_is_rejected_by_default():
    identity = PrivilegeIdentity(uid=0, gid=0)

    result = enforce_least_privilege(identity)

    assert result.allowed is False
    assert result.is_root is True
    assert result.reason == "ROOT_PRIVILEGE_FORBIDDEN"


def test_root_can_only_be_allowed_explicitly():
    identity = PrivilegeIdentity(uid=0, gid=0)
    policy = LeastPrivilegePolicy(
        allow_root=True,
        minimum_uid=0,
        minimum_gid=0,
    )

    result = enforce_least_privilege(identity, policy)

    assert result.allowed is True


def test_root_still_fails_when_minimum_uid_is_one():
    identity = PrivilegeIdentity(uid=0, gid=0)
    policy = LeastPrivilegePolicy(
        allow_root=True,
        minimum_uid=1,
        minimum_gid=0,
    )

    result = enforce_least_privilege(identity, policy)

    assert result.allowed is False
    assert result.reason == "UID_BELOW_MINIMUM"


@pytest.mark.parametrize(
    "uid,gid",
    [
        (-1, 1000),
        (1000, -1),
    ],
)
def test_negative_identity_values_are_rejected(uid, gid):
    with pytest.raises(LeastPrivilegeError):
        enforce_least_privilege(
            PrivilegeIdentity(uid=uid, gid=gid)
        )


@pytest.mark.parametrize(
    "uid,gid",
    [
        (True, 1000),
        (1000, False),
    ],
)
def test_boolean_identity_values_are_rejected(uid, gid):
    with pytest.raises(LeastPrivilegeError):
        enforce_least_privilege(
            PrivilegeIdentity(uid=uid, gid=gid)
        )


def test_invalid_identity_type_is_rejected():
    with pytest.raises(TypeError):
        enforce_least_privilege(object())


def test_policy_rejects_boolean_minimum_uid():
    with pytest.raises(TypeError):
        LeastPrivilegePolicy(minimum_uid=True)


def test_policy_rejects_boolean_minimum_gid():
    with pytest.raises(TypeError):
        LeastPrivilegePolicy(minimum_gid=False)


def test_policy_rejects_negative_minimum_uid():
    with pytest.raises(LeastPrivilegeError):
        LeastPrivilegePolicy(minimum_uid=-1)


def test_policy_rejects_negative_minimum_gid():
    with pytest.raises(LeastPrivilegeError):
        LeastPrivilegePolicy(minimum_gid=-1)


def test_get_current_identity_uses_effective_ids():
    identity = get_current_identity(
        geteuid=lambda: 1000,
        getegid=lambda: 1001,
    )

    assert identity.uid == 1000
    assert identity.gid == 1001
    assert identity.is_root is False


def test_get_current_identity_rejects_invalid_uid():
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: -1,
            getegid=lambda: 1000,
        )


def test_get_current_identity_rejects_invalid_gid():
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: 1000,
            getegid=lambda: -1,
        )


def test_get_current_identity_rejects_boolean_uid():
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: True,
            getegid=lambda: 1000,
        )


def test_get_current_identity_rejects_boolean_gid():
    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=lambda: 1000,
            getegid=lambda: False,
        )


def test_get_current_identity_failure_is_wrapped():
    def broken_uid():
        raise OSError("identity unavailable")

    with pytest.raises(LeastPrivilegeError):
        get_current_identity(
            geteuid=broken_uid,
            getegid=lambda: 1000,
        )


def test_result_to_dict_is_serializable():
    identity = PrivilegeIdentity(
        uid=1000,
        gid=1000,
        username="runner",
        groupname="runner",
    )

    result = enforce_least_privilege(identity)
    data = result.to_dict()

    assert data["allowed"] is True
    assert data["identity"]["uid"] == 1000
    assert data["identity"]["gid"] == 1000
    assert data["identity"]["is_root"] is False


def test_current_runner_should_satisfy_least_privilege():
    result = validate_current_least_privilege()

    assert result.identity is not None
    assert result.uid is not None
    assert result.gid is not None

    if result.uid == 0:
        pytest.fail("GitHub Actions runner must not execute Task 187 as root")

    assert result.allowed is True


def test_require_least_privilege_returns_valid_result():
    result = require_least_privilege()

    assert result.allowed is True
    assert result.identity is not None
    assert result.is_root is False
