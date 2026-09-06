from sentinelshield.audit_log import AuditLog
from sentinelshield.violation_event_bridge import ViolationEvent


def make_event(reason="RESOURCE_LIMIT"):
    return ViolationEvent(
        event_type="POLICY_VIOLATION",
        timestamp="2026-01-01T00:00:00+00:00",
        decision="BLOCK",
        failures=("CPU", "RAM"),
        reason=reason,
    )


def test_append_and_read(tmp_path):
    log = AuditLog(
        tmp_path / "audit.jsonl"
    )

    event = make_event()

    log.append(event)

    records = log.read_all()

    assert len(records) == 1
    assert records[0]["event_type"] == "POLICY_VIOLATION"
    assert records[0]["decision"] == "BLOCK"


def test_multiple_events_are_preserved(tmp_path):
    log = AuditLog(
        tmp_path / "audit.jsonl"
    )

    log.append(make_event("CPU_LIMIT"))
    log.append(make_event("RAM_LIMIT"))

    records = log.read_all()

    assert len(records) == 2
    assert records[0]["reason"] == "CPU_LIMIT"
    assert records[1]["reason"] == "RAM_LIMIT"


def test_missing_log_returns_empty_list(tmp_path):
    log = AuditLog(
        tmp_path / "missing.jsonl"
    )

    assert log.read_all() == []


def test_failures_are_serialized(tmp_path):
    log = AuditLog(
        tmp_path / "audit.jsonl"
    )

    log.append(make_event())

    record = log.read_all()[0]

    assert record["failures"] == [
        "CPU",
        "RAM",
    ]


def test_log_is_append_only(tmp_path):
    log = AuditLog(
        tmp_path / "audit.jsonl"
    )

    log.append(make_event("FIRST"))
    log.append(make_event("SECOND"))

    records = log.read_all()

    assert [
        record["reason"]
        for record in records
    ] == [
        "FIRST",
        "SECOND",
    ]


def test_parent_directory_is_created(tmp_path):
    log = AuditLog(
        tmp_path
        / "nested"
        / "audit.jsonl"
    )

    log.append(make_event())

    assert log.path.exists()


def test_each_record_is_json_line(tmp_path):
    log = AuditLog(
        tmp_path / "audit.jsonl"
    )

    log.append(make_event())

    lines = log.path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1
    assert lines[0].startswith("{")
    assert lines[0].endswith("}")


def test_empty_lines_are_ignored(tmp_path):
    path = tmp_path / "audit.jsonl"

    path.write_text(
        "\n\n",
        encoding="utf-8",
    )

    log = AuditLog(path)

    assert log.read_all() == []
