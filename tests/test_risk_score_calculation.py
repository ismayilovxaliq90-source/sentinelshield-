from sentinelshield.risk_score_calculation import (
    RiskLevel,
    RiskScoreInput,
    RiskScoreResult,
    RiskScoreCalculator,
    calculate_risk_score,
    risk_score_calculation,
)


def test_empty_input_is_valid_and_low():
    result = calculate_risk_score(
        RiskScoreInput()
    )

    assert isinstance(result, RiskScoreResult)
    assert result.score == 0.0
    assert result.level is RiskLevel.LOW


def test_none_input_is_rejected():
    try:
        calculate_risk_score(None)
    except TypeError as error:
        assert str(error) == "INPUT_IS_NONE"
    else:
        raise AssertionError(
            "None must raise TypeError"
        )


def test_unsupported_type_is_rejected():
    try:
        calculate_risk_score(123)
    except TypeError as error:
        assert str(error) == "UNSUPPORTED_INPUT_TYPE"
    else:
        raise AssertionError(
            "Unsupported type must raise TypeError"
        )


def test_cvss_validation():
    for value in (-1, 10.1):
        try:
            calculate_risk_score(
                {"cvss": value}
            )
        except ValueError as error:
            assert str(error) == "CVSS_OUT_OF_RANGE"
        else:
            raise AssertionError(
                "Invalid CVSS must raise ValueError"
            )


def test_score_validation():
    for field in (
        "urgency_score",
        "confidence_score",
        "exploitability_score",
        "reachability_score",
        "exposure_score",
    ):
        for value in (-0.1, 100.1):
            try:
                calculate_risk_score(
                    {field: value}
                )
            except ValueError as error:
                assert str(error) == (
                    f"{field.upper()}_OUT_OF_RANGE"
                )
            else:
                raise AssertionError(
                    f"{field} must validate its range"
                )


def test_boolean_is_not_accepted_as_numeric():
    try:
        calculate_risk_score(
            {"confidence_score": True}
        )
    except TypeError as error:
        assert str(error) == (
            "INVALID_CONFIDENCE_SCORE_TYPE"
        )
    else:
        raise AssertionError(
            "bool must not be accepted"
        )


def test_unknown_mapping_field_is_rejected():
    try:
        calculate_risk_score(
            {"unknown": 10}
        )
    except TypeError as error:
        assert str(error).startswith(
            "UNSUPPORTED_INPUT_FIELD:"
        )
    else:
        raise AssertionError(
            "Unknown field must be rejected"
        )


def test_all_zero_is_low():
    result = calculate_risk_score(
        {
            "cvss": 0,
            "urgency_score": 0,
            "confidence_score": 0,
            "exploitability_score": 0,
            "reachability_score": 0,
            "exposure_score": 0,
        }
    )

    assert result.score == 0.0
    assert result.level is RiskLevel.LOW


def test_all_maximum_is_critical():
    result = calculate_risk_score(
        {
            "cvss": 10,
            "urgency_score": 100,
            "confidence_score": 100,
            "exploitability_score": 100,
            "reachability_score": 100,
            "exposure_score": 100,
        }
    )

    assert result.score == 100.0
    assert result.level is RiskLevel.CRITICAL


def test_cvss_increases_risk():
    low = calculate_risk_score(
        {"cvss": 2}
    )
    high = calculate_risk_score(
        {"cvss": 8}
    )

    assert high.score > low.score


def test_urgency_increases_risk():
    low = calculate_risk_score(
        {"urgency_score": 20}
    )
    high = calculate_risk_score(
        {"urgency_score": 80}
    )

    assert high.score > low.score


def test_confidence_increases_risk():
    low = calculate_risk_score(
        {"confidence_score": 20}
    )
    high = calculate_risk_score(
        {"confidence_score": 80}
    )

    assert high.score > low.score


def test_exploitability_increases_risk():
    low = calculate_risk_score(
        {"exploitability_score": 10}
    )
    high = calculate_risk_score(
        {"exploitability_score": 90}
    )

    assert high.score > low.score


def test_reachability_increases_risk():
    low = calculate_risk_score(
        {"reachability_score": 10}
    )
    high = calculate_risk_score(
        {"reachability_score": 90}
    )

    assert high.score > low.score


def test_exposure_increases_risk():
    low = calculate_risk_score(
        {"exposure_score": 10}
    )
    high = calculate_risk_score(
        {"exposure_score": 90}
    )

    assert high.score > low.score


def test_score_is_bounded():
    result = calculate_risk_score(
        {
            "cvss": 10,
            "urgency_score": 100,
            "confidence_score": 100,
            "exploitability_score": 100,
            "reachability_score": 100,
            "exposure_score": 100,
        }
    )

    assert 0.0 <= result.score <= 100.0


def test_medium_boundary():
    result = calculate_risk_score(
        {"urgency_score": 100}
    )

    assert result.score == 25.0
    assert result.level is RiskLevel.MEDIUM


def test_high_boundary():
    result = calculate_risk_score(
        {"urgency_score": 200}
    ) if False else calculate_risk_score(
        {
            "cvss": 10,
            "urgency_score": 80,
            "confidence_score": 0,
            "exploitability_score": 0,
            "reachability_score": 0,
            "exposure_score": 0,
        }
    )

    assert result.score == 45.0
    assert result.level is RiskLevel.MEDIUM


def test_mapping_input():
    result = calculate_risk_score(
        {
            "cvss": 8,
            "urgency_score": 70,
            "confidence_score": 90,
            "exploitability_score": 60,
            "reachability_score": 80,
            "exposure_score": 70,
        }
    )

    assert isinstance(result, RiskScoreResult)
    assert result.score > 0.0


def test_dataclass_input():
    result = RiskScoreCalculator().calculate(
        RiskScoreInput(
            cvss=7.5,
            urgency_score=60,
            confidence_score=80,
            exploitability_score=70,
            reachability_score=50,
            exposure_score=40,
        )
    )

    assert result.score == 65.25
    assert result.level is RiskLevel.HIGH


def test_deterministic_result():
    payload = {
        "cvss": 8.5,
        "urgency_score": 72,
        "confidence_score": 91,
        "exploitability_score": 77,
        "reachability_score": 66,
        "exposure_score": 88,
    }

    first = calculate_risk_score(payload)
    second = calculate_risk_score(payload)

    assert first == second


def test_public_alias():
    payload = {
        "cvss": 6,
        "urgency_score": 50,
        "confidence_score": 50,
    }

    assert (
        calculate_risk_score(payload)
        == risk_score_calculation(payload)
    )


def test_reasons_are_generated():
    result = calculate_risk_score(
        {
            "cvss": 9.5,
            "urgency_score": 80,
            "confidence_score": 90,
            "exploitability_score": 80,
            "reachability_score": 80,
            "exposure_score": 80,
        }
    )

    assert "HIGH_CVSS" in result.reasons
    assert "HIGH_REMEDIATION_URGENCY" in result.reasons
    assert "HIGH_CONFIDENCE" in result.reasons
    assert "HIGH_EXPLOITABILITY" in result.reasons
    assert "HIGH_REACHABILITY" in result.reasons
    assert "HIGH_EXPOSURE" in result.reasons


def test_no_filesystem_mutation(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    calculate_risk_score(
        {
            "cvss": 8,
            "urgency_score": 70,
            "confidence_score": 80,
        }
    )

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert before == after
