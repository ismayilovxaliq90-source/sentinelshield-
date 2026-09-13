from dataclasses import dataclass


class DeliveryPackageGenerationError(ValueError):
    pass


@dataclass(frozen=True)
class DeliveryPackageGenerationInput:
    package_id: str
    status: str
    dependency_inventory_reference: str
    vulnerability_inventory_reference: str
    remediation_report_reference: str
    evidence_count: int
    package_digest: str
    audit_reference: str


DeliveryPackage = DeliveryPackageGenerationInput


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeliveryPackageGenerationError(
            f"{name.upper()}_MUST_BE_NONEMPTY_STRING"
        )
    return value.strip()


def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeliveryPackageGenerationError(
            f"{name.upper()}_MUST_BE_INTEGER"
        )
    if value < 0:
        raise DeliveryPackageGenerationError(
            f"{name.upper()}_MUST_BE_NONNEGATIVE"
        )
    return value


def validate_delivery_package(
    package: DeliveryPackageGenerationInput,
) -> DeliveryPackageGenerationInput:
    if not isinstance(package, DeliveryPackageGenerationInput):
        raise TypeError("INPUT_MUST_BE_DELIVERY_PACKAGE_GENERATION_INPUT")

    for name in (
        "package_id",
        "status",
        "dependency_inventory_reference",
        "vulnerability_inventory_reference",
        "remediation_report_reference",
        "package_digest",
        "audit_reference",
    ):
        _text(getattr(package, name), name)

    _count(package.evidence_count, "evidence_count")

    if package.status.strip().lower() not in {
        "ready",
        "complete",
        "final",
    }:
        raise DeliveryPackageGenerationError("INVALID_PACKAGE_STATUS")

    return package


def create_delivery_package(
    package_id: str,
    status: str,
    dependency_inventory_reference: str,
    vulnerability_inventory_reference: str,
    remediation_report_reference: str,
    evidence_count: int,
    package_digest: str,
    audit_reference: str,
) -> DeliveryPackageGenerationInput:
    package = DeliveryPackageGenerationInput(
        package_id=_text(package_id, "package_id"),
        status=_text(status, "status"),
        dependency_inventory_reference=_text(
            dependency_inventory_reference,
            "dependency_inventory_reference",
        ),
        vulnerability_inventory_reference=_text(
            vulnerability_inventory_reference,
            "vulnerability_inventory_reference",
        ),
        remediation_report_reference=_text(
            remediation_report_reference,
            "remediation_report_reference",
        ),
        evidence_count=evidence_count,
        package_digest=_text(package_digest, "package_digest"),
        audit_reference=_text(audit_reference, "audit_reference"),
    )
    return validate_delivery_package(package)
