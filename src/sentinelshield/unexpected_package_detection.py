from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


__test__ = False


@dataclass(frozen=True)
class UnexpectedPackage:
    name: str
    version: str | None
    status: str
    expected: bool
    reason: str


@dataclass(frozen=True)
class UnexpectedPackageDetectionInput:
    expected_packages: Mapping[str, str | None]
    actual_packages: Mapping[str, str | None]


@dataclass(frozen=True)
class UnexpectedPackageDetectionResult:
    packages: tuple[UnexpectedPackage, ...]

    @property
    def unexpected(self) -> tuple[UnexpectedPackage, ...]:
        return tuple(
            item for item in self.packages
            if item.status == "UNEXPECTED"
        )

    @property
    def expected(self) -> tuple[UnexpectedPackage, ...]:
        return tuple(
            item for item in self.packages
            if item.status == "EXPECTED"
        )

    @property
    def missing(self) -> tuple[UnexpectedPackage, ...]:
        return tuple(
            item for item in self.packages
            if item.status == "MISSING"
        )

    @property
    def has_unexpected(self) -> bool:
        return bool(self.unexpected)


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _normalize_version(
    version: str | None,
) -> str | None:
    if version is None:
        return None

    if not isinstance(version, str):
        raise TypeError("PACKAGE_VERSION_MUST_BE_STRING_OR_NONE")

    value = version.strip()

    return value or None


def _validate_input(
    request: UnexpectedPackageDetectionInput,
) -> UnexpectedPackageDetectionInput:
    if not isinstance(
        request,
        UnexpectedPackageDetectionInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_UNEXPECTED_PACKAGE_DETECTION_INPUT"
        )

    if not isinstance(request.expected_packages, Mapping):
        raise TypeError("EXPECTED_PACKAGES_MUST_BE_MAPPING")

    if not isinstance(request.actual_packages, Mapping):
        raise TypeError("ACTUAL_PACKAGES_MUST_BE_MAPPING")

    expected: dict[str, str | None] = {}

    for name, version in request.expected_packages.items():
        if not isinstance(name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING")

        normalized = _normalize_name(name)

        if not normalized:
            raise ValueError("PACKAGE_NAME_IS_EMPTY")

        expected[normalized] = _normalize_version(version)

    actual: dict[str, str | None] = {}

    for name, version in request.actual_packages.items():
        if not isinstance(name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING")

        normalized = _normalize_name(name)

        if not normalized:
            raise ValueError("PACKAGE_NAME_IS_EMPTY")

        actual[normalized] = _normalize_version(version)

    return UnexpectedPackageDetectionInput(
        expected_packages=expected,
        actual_packages=actual,
    )


def detect_unexpected_packages(
    request: UnexpectedPackageDetectionInput,
) -> UnexpectedPackageDetectionResult:
    request = _validate_input(request)

    expected = request.expected_packages
    actual = request.actual_packages

    results: list[UnexpectedPackage] = []

    for name in sorted(actual):
        version = actual[name]

        if name not in expected:
            results.append(
                UnexpectedPackage(
                    name=name,
                    version=version,
                    status="UNEXPECTED",
                    expected=False,
                    reason="PACKAGE_NOT_IN_EXPECTED_INVENTORY",
                )
            )
            continue

        results.append(
            UnexpectedPackage(
                name=name,
                version=version,
                status="EXPECTED",
                expected=True,
                reason="PACKAGE_IN_EXPECTED_INVENTORY",
            )
        )

    for name in sorted(set(expected) - set(actual)):
        results.append(
            UnexpectedPackage(
                name=name,
                version=expected[name],
                status="MISSING",
                expected=True,
                reason="EXPECTED_PACKAGE_NOT_PRESENT",
            )
        )

    return UnexpectedPackageDetectionResult(
        packages=tuple(
            sorted(
                results,
                key=lambda item: item.name,
            )
        )
    )


def unexpected_package_detection(
    request: UnexpectedPackageDetectionInput,
) -> UnexpectedPackageDetectionResult:
    return detect_unexpected_packages(request)
