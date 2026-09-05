import os

import pytest

from sentinelshield.least_privilege import (
    LeastPrivilegeController,
    PrivilegeViolation,
)


def test_inspect_returns_privilege_state():
    controller = LeastPrivilegeController()

    state = controller.inspect()

    assert isinstance(state.uid, int)
    assert isinstance(state.euid, int)
    assert isinstance(state.gid, int)
    assert isinstance(state.egid, int)
    assert isinstance(state.is_root, bool)
    assert isinstance(state.elevated, bool)


def test_normal_non_root_execution_is_allowed(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)

    controller = LeastPrivilegeController()

    state = controller.validate()

    assert state.uid == 1000
    assert state.euid == 1000
    assert state.is_root is False
    assert state.elevated is False


def test_root_execution_is_blocked_by_default(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController()

    with pytest.raises(PrivilegeViolation):
        controller.validate()


def test_root_execution_can_be_explicitly_allowed(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController(
        allow_root=True
    )

    state = controller.validate()

    assert state.is_root is True


def test_effective_uid_change_is_detected(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)

    controller = LeastPrivilegeController()

    state = controller.inspect()

    assert state.elevated is True
    assert state.is_root is True


def test_effective_gid_change_is_detected(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController()

    state = controller.inspect()

    assert state.elevated is True


def test_elevated_execution_is_blocked_by_default(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController()

    with pytest.raises(PrivilegeViolation):
        controller.validate()


def test_elevated_execution_can_be_explicitly_allowed(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController(
        allow_elevated=True
    )

    state = controller.validate()

    assert state.elevated is True


def test_is_allowed_returns_true_for_normal_user(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)

    controller = LeastPrivilegeController()

    assert controller.is_allowed() is True


def test_is_allowed_returns_false_for_root(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)

    controller = LeastPrivilegeController()

    assert controller.is_allowed() is False
