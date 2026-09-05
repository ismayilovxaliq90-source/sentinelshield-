import json

import pytest

from sentinelshield.evidence_collection import (
    EvidenceBundle,
    EvidenceCollectionError,
    EvidenceCollector,
    EvidenceItem,
)


def test_collector_can_be_created():
    collector = EvidenceCollector()

    assert collector.items() == ()


def test_add_creates_evidence_item():
    collector = EvidenceCollector()

    item = collector.add(
        "status",
        "PASS",
    )

    assert isinstance(item, EvidenceItem)
    assert item.name == "status"
    assert item.value == "PASS"


def test_item_digest_is_sha256():
    collector = EvidenceCollector()

    item = collector.add(
        "status",
        "PASS",
    )

    assert len(item.digest) == 64
    assert all(
        character in "0123456789abcdef"
        for character in item.digest
    )


def test_same_value_has_same_digest():
    collector = EvidenceCollector()

    first = collector.add(
        "a",
        "same",
    )

    second = collector.add(
        "b",
        "same",
    )

    assert first.digest == second.digest


def test_empty_name_is_rejected():
    collector = EvidenceCollector()

    with pytest.raises(ValueError):
        collector.add("", "value")


def test_invalid_name_type_is_rejected():
    collector = EvidenceCollector()

    with pytest.raises(TypeError):
        collector.add(123, "value")


def test_secret_password_is_redacted():
    collector = EvidenceCollector()

    item = collector.add(
        "message",
        "password=SUPER_SECRET",
    )

    assert "SUPER_SECRET" not in item.value
    assert "[REDACTED]" in item.value


def test_secret_token_is_redacted():
    collector = EvidenceCollector()

    item = collector.add(
        "message",
        "token: SUPER_SECRET_TOKEN",
    )

    assert "SUPER_SECRET_TOKEN" not in item.value


def test_normal_value_is_preserved():
    collector = EvidenceCollector()

    item = collector.add(
        "status",
        "execution completed",
    )

    assert item.value == "execution completed"


def test_non_string_value_is_converted_safely():
    collector = EvidenceCollector()

    item = collector.add(
        "return_code",
        0,
    )

    assert item.value == "0"


def test_collect_requires_execution_id():
    collector = EvidenceCollector()

    with pytest.raises(ValueError):
        collector.collect(
            "",
            {"status": "PASS"},
        )


def test_collect_requires_dictionary():
    collector = EvidenceCollector()

    with pytest.raises(TypeError):
        collector.collect(
            "exec-1",
            [],
        )


def test_collect_returns_bundle():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {
            "status": "PASS",
            "return_code": 0,
        },
    )

    assert isinstance(bundle, EvidenceBundle)
    assert bundle.execution_id == "exec-1"


def test_collect_sorts_evidence_names():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {
            "z": "Z",
            "a": "A",
            "m": "M",
        },
    )

    assert [
        item.name
        for item in bundle.items
    ] == [
        "a",
        "m",
        "z",
    ]


def test_collect_creates_bundle_digest():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {
            "status": "PASS",
        },
    )

    assert len(bundle.bundle_digest) == 64


def test_same_evidence_produces_same_bundle_digest():
    first_collector = EvidenceCollector()
    second_collector = EvidenceCollector()

    first = first_collector.collect(
        "exec-1",
        {
            "status": "PASS",
            "code": 0,
        },
    )

    second = second_collector.collect(
        "exec-1",
        {
            "code": 0,
            "status": "PASS",
        },
    )

    assert first.bundle_digest == second.bundle_digest


def test_different_evidence_produces_different_bundle_digest():
    collector = EvidenceCollector()

    first = collector.collect(
        "exec-1",
        {"status": "PASS"},
    )

    second = collector.collect(
        "exec-1",
        {"status": "FAIL"},
    )

    assert first.bundle_digest != second.bundle_digest


def test_collect_replaces_previous_items():
    collector = EvidenceCollector()

    collector.add("old", "value")

    bundle = collector.collect(
        "exec-1",
        {"new": "value"},
    )

    assert [
        item.name
        for item in bundle.items
    ] == ["new"]


def test_items_returns_tuple():
    collector = EvidenceCollector()

    collector.add("status", "PASS")

    assert isinstance(
        collector.items(),
        tuple,
    )


def test_evidence_item_is_immutable():
    collector = EvidenceCollector()

    item = collector.add(
        "status",
        "PASS",
    )

    with pytest.raises(AttributeError):
        item.value = "FAIL"


def test_evidence_bundle_is_immutable():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {"status": "PASS"},
    )

    with pytest.raises(AttributeError):
        bundle.execution_id = "other"


def test_clear_removes_items():
    collector = EvidenceCollector()

    collector.add("status", "PASS")

    collector.clear()

    assert collector.items() == ()


def test_digest_rejects_non_string():
    with pytest.raises(TypeError):
        EvidenceCollector.digest(123)


def test_redact_rejects_non_string():
    with pytest.raises(TypeError):
        EvidenceCollector.redact(123)


def test_redaction_preserves_variable_name():
    collector = EvidenceCollector()

    item = collector.add(
        "env",
        "API_KEY=SECRET123",
    )

    assert item.value == "API_KEY=[REDACTED]"


def test_bundle_contains_all_items():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {
            "status": "PASS",
            "code": 0,
            "duration": "1.2",
        },
    )

    assert len(bundle.items) == 3


def test_bundle_items_are_tuple():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {"status": "PASS"},
    )

    assert isinstance(
        bundle.items,
        tuple,
    )


def test_redacted_secret_does_not_remain_in_bundle():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {
            "message": "token=VERY_SECRET_VALUE",
        },
    )

    serialized = json.dumps(
        {
            "execution_id": bundle.execution_id,
            "items": [
                {
                    "name": item.name,
                    "value": item.value,
                    "digest": item.digest,
                }
                for item in bundle.items
            ],
            "bundle_digest": bundle.bundle_digest,
        }
    )

    assert "VERY_SECRET_VALUE" not in serialized


def test_empty_evidence_creates_empty_bundle():
    collector = EvidenceCollector()

    bundle = collector.collect(
        "exec-1",
        {},
    )

    assert bundle.items == ()
    assert len(bundle.bundle_digest) == 64
