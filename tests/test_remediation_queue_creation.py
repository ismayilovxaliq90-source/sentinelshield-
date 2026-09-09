import pytest

from sentinelshield.remediation_queue_creation import (
    QueueAction,
    QueuePriority,
    RemediationQueueInput,
    create_remediation_queue,
    remediation_queue_creation,
)


def _item(
    vid,
    score,
    risk,
    action,
    priority,
):
    return {
        "vulnerability_id": vid,
        "triage_score": score,
        "risk_level": risk,
        "recommended_action": action,
        "analyst_priority": priority,
    }


def test_empty_queue():
    result = create_remediation_queue([])

    assert result.items == ()
    assert result.total == 0


def test_critical_item():
    result = create_remediation_queue(
        [
            _item(
                "CVE-CRITICAL",
                90,
                "CRITICAL",
                "IMMEDIATE_RESPONSE",
                "CRITICAL",
            )
        ]
    )

    item = result.items[0]

    assert item.queue_rank == 1
    assert item.priority is QueuePriority.CRITICAL
    assert item.action is QueueAction.IMMEDIATE_REMEDIATION


def test_high_item():
    result = create_remediation_queue(
        [
            _item(
                "CVE-HIGH",
                60,
                "HIGH",
                "INVESTIGATE",
                "HIGH",
            )
        ]
    )

    item = result.items[0]

    assert item.priority is QueuePriority.HIGH
    assert item.action is QueueAction.REMEDIATION_REVIEW


def test_medium_item():
    result = create_remediation_queue(
        [
            _item(
                "CVE-MEDIUM",
                35,
                "MEDIUM",
                "REVIEW",
                "MEDIUM",
            )
        ]
    )

    item = result.items[0]

    assert item.priority is QueuePriority.MEDIUM
    assert item.action is QueueAction.SCHEDULE_REMEDIATION


def test_low_item():
    result = create_remediation_queue(
        [
            _item(
                "CVE-LOW",
                10,
                "LOW",
                "MONITOR",
                "LOW",
            )
        ]
    )

    item = result.items[0]

    assert item.priority is QueuePriority.LOW
    assert item.action is QueueAction.MONITOR


def test_highest_priority_first():
    result = create_remediation_queue(
        [
            _item("LOW", 10, "LOW", "MONITOR", "LOW"),
            _item("CRITICAL", 90, "CRITICAL", "IMMEDIATE_RESPONSE", "CRITICAL"),
            _item("MEDIUM", 35, "MEDIUM", "REVIEW", "MEDIUM"),
            _item("HIGH", 60, "HIGH", "INVESTIGATE", "HIGH"),
        ]
    )

    assert [x.vulnerability_id for x in result.items] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]


def test_same_priority_uses_score_descending():
    result = create_remediation_queue(
        [
            _item("HIGH-LOWER", 55, "HIGH", "INVESTIGATE", "HIGH"),
            _item("HIGH-HIGHER", 70, "HIGH", "INVESTIGATE", "HIGH"),
        ]
    )

    assert [x.vulnerability_id for x in result.items] == [
        "HIGH-HIGHER",
        "HIGH-LOWER",
    ]


def test_equal_score_preserves_input_order():
    result = create_remediation_queue(
        [
            _item("FIRST", 60, "HIGH", "INVESTIGATE", "HIGH"),
            _item("SECOND", 60, "HIGH", "INVESTIGATE", "HIGH"),
            _item("THIRD", 60, "HIGH", "INVESTIGATE", "HIGH"),
        ]
    )

    assert [x.vulnerability_id for x in result.items] == [
        "FIRST",
        "SECOND",
        "THIRD",
    ]


def test_sequential_ranks():
    result = create_remediation_queue(
        [
            _item("A", 90, "CRITICAL", "IMMEDIATE_RESPONSE", "CRITICAL"),
            _item("B", 60, "HIGH", "INVESTIGATE", "HIGH"),
            _item("C", 30, "MEDIUM", "REVIEW", "MEDIUM"),
        ]
    )

    assert [x.queue_rank for x in result.items] == [1, 2, 3]


def test_total_matches_items():
    result = create_remediation_queue(
        [
            _item("A", 90, "CRITICAL", "IMMEDIATE_RESPONSE", "CRITICAL"),
            _item("B", 20, "LOW", "MONITOR", "LOW"),
        ]
    )

    assert result.total == 2
    assert result.total == len(result.items)


def test_dataclass_input():
    result = create_remediation_queue(
        [
            RemediationQueueInput(
                vulnerability_id="CVE-DATA",
                triage_score=80,
                risk_level="CRITICAL",
                recommended_action="IMMEDIATE_RESPONSE",
                analyst_priority="CRITICAL",
            )
        ]
    )

    assert result.items[0].vulnerability_id == "CVE-DATA"
    assert result.items[0].priority is QueuePriority.CRITICAL


def test_mapping_input():
    result = create_remediation_queue(
        [
            _item(
                "CVE-MAP",
                80,
                "CRITICAL",
                "IMMEDIATE_RESPONSE",
                "CRITICAL",
            )
        ]
    )

    assert result.items[0].vulnerability_id == "CVE-MAP"


def test_input_immutability():
    source = [
        _item(
            "A",
            90,
            "CRITICAL",
            "IMMEDIATE_RESPONSE",
            "CRITICAL",
        ),
        _item(
            "B",
            20,
            "LOW",
            "MONITOR",
            "LOW",
        ),
    ]

    original = [dict(item) for item in source]

    create_remediation_queue(source)

    assert source == original


def test_deterministic_result():
    source = [
        _item("A", 90, "CRITICAL", "IMMEDIATE_RESPONSE", "CRITICAL"),
        _item("B", 60, "HIGH", "INVESTIGATE", "HIGH"),
        _item("C", 30, "MEDIUM", "REVIEW", "MEDIUM"),
    ]

    first = create_remediation_queue(source)
    second = create_remediation_queue(source)

    assert first == second


def test_none_top_level_rejected():
    with pytest.raises(TypeError):
        create_remediation_queue(None)


def test_string_top_level_rejected():
    with pytest.raises(TypeError):
        create_remediation_queue("invalid")


def test_none_item_rejected():
    with pytest.raises(ValueError, match="index 0"):
        create_remediation_queue([None])


def test_unsupported_item_rejected():
    with pytest.raises(TypeError):
        create_remediation_queue([123])


def test_missing_field_rejected():
    with pytest.raises(ValueError):
        create_remediation_queue(
            [
                {
                    "vulnerability_id": "CVE-1",
                    "triage_score": 50,
                }
            ]
        )


def test_unknown_field_rejected():
    with pytest.raises(TypeError):
        create_remediation_queue(
            [
                {
                    **_item(
                        "CVE-1",
                        50,
                        "HIGH",
                        "INVESTIGATE",
                        "HIGH",
                    ),
                    "unexpected": "value",
                }
            ]
        )


def test_boolean_score_rejected():
    with pytest.raises(TypeError):
        create_remediation_queue(
            [
                _item(
                    "CVE-1",
                    True,
                    "HIGH",
                    "INVESTIGATE",
                    "HIGH",
                )
            ]
        )


def test_negative_score_rejected():
    with pytest.raises(ValueError):
        create_remediation_queue(
            [
                _item(
                    "CVE-1",
                    -1,
                    "LOW",
                    "MONITOR",
                    "LOW",
                )
            ]
        )


def test_score_above_100_rejected():
    with pytest.raises(ValueError):
        create_remediation_queue(
            [
                _item(
                    "CVE-1",
                    101,
                    "CRITICAL",
                    "IMMEDIATE_RESPONSE",
                    "CRITICAL",
                )
            ]
        )


def test_public_alias():
    source = [
        _item(
            "CVE-ALIAS",
            80,
            "CRITICAL",
            "IMMEDIATE_RESPONSE",
            "CRITICAL",
        )
    ]

    assert remediation_queue_creation(source) == create_remediation_queue(
        source
    )


def test_priority_can_fallback_to_risk_level():
    result = create_remediation_queue(
        [
            _item(
                "CVE-FALLBACK",
                80,
                "CRITICAL",
                "IMMEDIATE_RESPONSE",
                "UNKNOWN",
            )
        ]
    )

    assert result.items[0].priority is QueuePriority.CRITICAL


def test_score_fallback():
    result = create_remediation_queue(
        [
            _item(
                "CVE-SCORE",
                70,
                "UNKNOWN",
                "UNKNOWN",
                "UNKNOWN",
            )
        ]
    )

    assert result.items[0].priority is QueuePriority.HIGH


def test_result_is_immutable():
    result = create_remediation_queue(
        [
            _item(
                "CVE-IMMUTABLE",
                90,
                "CRITICAL",
                "IMMEDIATE_RESPONSE",
                "CRITICAL",
            )
        ]
    )

    with pytest.raises(AttributeError):
        result.total = 5
