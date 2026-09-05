import pytest

from sentinelshield.deterministic_validation import (
    DeterministicValidationError,
    DeterministicValidator,
    ValidationResult,
)


def test_validator_can_be_created():
    validator = DeterministicValidator()

    assert validator is not None


def test_simple_data_can_be_canonicalized():
    validator = DeterministicValidator()

    result = validator.canonicalize(
        {"name": "sentinelshield"}
    )

    assert result == '{"name":"sentinelshield"}'


def test_dictionary_key_order_is_normalized():
    validator = DeterministicValidator()

    first = validator.canonicalize(
        {"a": 1, "b": 2}
    )

    second = validator.canonicalize(
        {"b": 2, "a": 1}
    )

    assert first == second


def test_equal_data_produces_equal_digest():
    validator = DeterministicValidator()

    first = validator.validate(
        {"a": 1, "b": 2}
    )

    second = validator.validate(
        {"b": 2, "a": 1}
    )

    assert first.digest == second.digest


def test_different_data_produces_different_digest():
    validator = DeterministicValidator()

    first = validator.validate(
        {"value": 1}
    )

    second = validator.validate(
        {"value": 2}
    )

    assert first.digest != second.digest


def test_digest_has_sha256_length():
    validator = DeterministicValidator()

    result = validator.validate(
        {"value": "test"}
    )

    assert len(result.digest) == 64


def test_digest_contains_hex_characters_only():
    validator = DeterministicValidator()

    result = validator.validate(
        {"value": "test"}
    )

    assert all(
        character in "0123456789abcdef"
        for character in result.digest
    )


def test_validation_returns_validation_result():
    validator = DeterministicValidator()

    result = validator.validate(
        {"status": "OK"}
    )

    assert isinstance(result, ValidationResult)


def test_normal_validation_is_valid():
    validator = DeterministicValidator()

    result = validator.validate(
        {"status": "OK"}
    )

    assert result.valid is True
    assert result.reason == "validation passed"


def test_expected_digest_can_validate_result():
    validator = DeterministicValidator()

    data = {
        "status": "OK",
        "count": 1,
    }

    first = validator.validate(data)

    second = validator.validate(
        data,
        expected_digest=first.digest,
    )

    assert second.valid is True
    assert second.digest == first.digest


def test_wrong_digest_is_rejected():
    validator = DeterministicValidator()

    result = validator.validate(
        {"status": "OK"},
        expected_digest="0" * 64,
    )

    assert result.valid is False
    assert result.reason == "digest mismatch"


def test_matches_returns_true_for_correct_digest():
    validator = DeterministicValidator()

    data = {"value": 123}
    digest = validator.validate(data).digest

    assert validator.matches(data, digest) is True


def test_matches_returns_false_for_wrong_digest():
    validator = DeterministicValidator()

    assert validator.matches(
        {"value": 123},
        "0" * 64,
    ) is False


def test_invalid_expected_digest_type_is_rejected():
    validator = DeterministicValidator()

    with pytest.raises(TypeError):
        validator.validate(
            {"value": 1},
            expected_digest=123,
        )


def test_invalid_canonical_input_type_is_rejected_for_digest():
    validator = DeterministicValidator()

    with pytest.raises(TypeError):
        validator.digest(123)


def test_non_serializable_data_is_rejected():
    validator = DeterministicValidator()

    with pytest.raises(DeterministicValidationError):
        validator.canonicalize(
            {"value": object()}
        )


def test_nested_structures_are_canonicalized():
    validator = DeterministicValidator()

    first = validator.canonicalize(
        {
            "outer": {
                "z": 2,
                "a": 1,
            },
            "items": [3, 2, 1],
        }
    )

    second = validator.canonicalize(
        {
            "items": [3, 2, 1],
            "outer": {
                "a": 1,
                "z": 2,
            },
        }
    )

    assert first == second


def test_list_order_is_preserved():
    validator = DeterministicValidator()

    first = validator.canonicalize(
        {"items": [1, 2, 3]}
    )

    second = validator.canonicalize(
        {"items": [3, 2, 1]}
    )

    assert first != second


def test_repeated_validation_is_stable():
    validator = DeterministicValidator()

    data = {
        "project": "sentinelshield",
        "task": 35,
        "status": "PASS",
    }

    results = [
        validator.validate(data)
        for _ in range(5)
    ]

    digests = {
        result.digest
        for result in results
    }

    assert len(digests) == 1
    assert all(
        result.valid is True
        for result in results
    )


def test_unicode_data_is_supported():
    validator = DeterministicValidator()

    result = validator.validate(
        {"message": "təhlükəsiz"}
    )

    assert result.valid is True


def test_boolean_and_none_are_supported():
    validator = DeterministicValidator()

    result = validator.validate(
        {
            "enabled": True,
            "value": None,
        }
    )

    assert result.valid is True


def test_empty_dictionary_is_supported():
    validator = DeterministicValidator()

    result = validator.validate({})

    assert result.valid is True


def test_empty_list_is_supported():
    validator = DeterministicValidator()

    result = validator.validate([])

    assert result.valid is True


def test_result_digest_matches_canonical_data():
    validator = DeterministicValidator()

    data = {"a": 1}
    canonical = validator.canonicalize(data)
    result = validator.validate(data)

    assert result.digest == validator.digest(canonical)
