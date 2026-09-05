from pathlib import Path

from sentinelshield.health_check import (
    HealthCheckResult,
    SentinelShieldHealthCheck,
)


def make_project(tmp_path):
    root = tmp_path / "sentinelshield"

    (root / "src" / "sentinelshield").mkdir(
        parents=True
    )

    (root / "tests").mkdir()

    return root


def test_healthy_project(tmp_path):
    root = make_project(tmp_path)

    audit = root / "runtime" / "audit.jsonl"
    alerts = root / "runtime" / "alerts.jsonl"

    audit.parent.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=audit,
        alert_path=alerts,
    ).run()

    assert isinstance(result, HealthCheckResult)
    assert result.healthy is True
    assert result.passed == result.total
    assert result.total == 5


def test_missing_project_root_is_unhealthy(tmp_path):
    root = tmp_path / "missing"

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=root / "audit.jsonl",
        alert_path=root / "alerts.jsonl",
    ).run()

    assert result.healthy is False


def test_missing_src_package(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "tests").mkdir()
    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=runtime / "alerts.jsonl",
    ).run()

    assert result.healthy is False
    assert result.checks["PROJECT_ROOT"] is True
    assert result.checks["SRC_PACKAGE"] is False


def test_missing_tests_directory(tmp_path):
    root = tmp_path / "project"

    (root / "src" / "sentinelshield").mkdir(
        parents=True
    )

    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=runtime / "alerts.jsonl",
    ).run()

    assert result.healthy is False
    assert result.checks["TESTS"] is False


def test_missing_audit_parent(tmp_path):
    root = make_project(tmp_path)

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=(
            root
            / "missing"
            / "audit.jsonl"
        ),
        alert_path=(
            root
            / "runtime"
            / "alerts.jsonl"
        ),
    ).run()

    assert result.healthy is False
    assert result.checks["AUDIT_PARENT"] is False


def test_missing_alert_parent(tmp_path):
    root = make_project(tmp_path)

    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=(
            root
            / "missing"
            / "alerts.jsonl"
        ),
    ).run()

    assert result.healthy is False
    assert result.checks["ALERT_PARENT"] is False


def test_passed_count(tmp_path):
    root = make_project(tmp_path)

    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=runtime / "alerts.jsonl",
    ).run()

    assert result.passed == 5


def test_result_is_immutable(tmp_path):
    root = make_project(tmp_path)

    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=runtime / "alerts.jsonl",
    ).run()

    try:
        result.healthy = False
        assert False
    except AttributeError:
        pass


def test_checks_are_boolean(tmp_path):
    root = make_project(tmp_path)

    runtime = root / "runtime"
    runtime.mkdir()

    result = SentinelShieldHealthCheck(
        project_root=root,
        audit_path=runtime / "audit.jsonl",
        alert_path=runtime / "alerts.jsonl",
    ).run()

    assert all(
        isinstance(value, bool)
        for value in result.checks.values()
    )
