import pytest

from sentinelshield.unexpected_package_detection import (
    UnexpectedPackageDetectionInput,
    detect_unexpected_packages,
)


def test_expected_package_is_accepted():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={"requests": "2.32.0"},
            actual_packages={"requests": "2.32.0"},
        )
    )

    assert result.has_unexpected is False
    assert result.expected[0].status == "EXPECTED"


def test_new_package_is_unexpected():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={"requests": "2.32.0"},
            actual_packages={
                "requests": "2.32.0",
                "malicious-package": "1.0.0",
            },
        )
    )

    assert len(result.unexpected) == 1
    assert result.unexpected[0].name == "malicious-package"
    assert result.unexpected[0].reason == (
        "PACKAGE_NOT_IN_EXPECTED_INVENTORY"
    )


def test_missing_expected_package_is_detected():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={
                "requests": "2.32.0",
                "urllib3": "2.2.0",
            },
            actual_packages={"requests": "2.32.0"},
        )
    )

    assert len(result.missing) == 1
    assert result.missing[0].name == "urllib3"


def test_package_name_normalization():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={"My_Package": "1.0"},
            actual_packages={"my-package": "1.0"},
        )
    )

    assert result.has_unexpected is False
    assert result.expected[0].name == "my-package"


def test_version_is_not_used_to_mark_package_unexpected():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={"requests": "2.31.0"},
            actual_packages={"requests": "2.32.0"},
        )
    )

    assert result.has_unexpected is False
    assert result.expected[0].version == "2.32.0"


def test_none_version_is_supported():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={"requests": None},
            actual_packages={"requests": None},
        )
    )

    assert result.has_unexpected is False


def test_results_are_sorted():
    result = detect_unexpected_packages(
        UnexpectedPackageDetectionInput(
            expected_packages={},
            actual_packages={
                "zeta": "1.0",
                "alpha": "1.0",
                "middle": "1.0",
            },
        )
    )

    assert [item.name for item in result.packages] == [
        "alpha",
        "middle",
        "zeta",
    ]


def test_empty_package_name_is_rejected():
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAME_IS_EMPTY",
    ):
        detect_unexpected_packages(
            UnexpectedPackageDetectionInput(
                expected_packages={"": "1.0"},
                actual_packages={},
            )
        )


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_UNEXPECTED_PACKAGE_DETECTION_INPUT",
    ):
        detect_unexpected_packages(None)


def test_non_string_package_name_is_rejected():
    with pytest.raises(
        TypeError,
        match="PACKAGE_NAME_MUST_BE_STRING",
    ):
        detect_unexpected_packages(
            UnexpectedPackageDetectionInput(
                expected_packages={123: "1.0"},
                actual_packages={},
            )
        )
