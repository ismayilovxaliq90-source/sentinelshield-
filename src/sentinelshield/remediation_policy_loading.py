from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class RemediationPolicy:
    policy_name: str
    version: str

    allowed_versions: tuple[str, ...]
    forbidden_versions: tuple[str, ...]

    maximum_upgrade_distance: int | None

    allow_major_upgrades: bool
    allow_production_dependencies: bool
    allow_development_dependencies: bool

    automated_remediation: bool
    manual_approval_required: bool

    risk_threshold: float | None
    change_scope: str
    dependency_policy: str


@dataclass(frozen=True)
class RemediationPolicyLoadingResult:
    policy: RemediationPolicy
    source: str
    loaded: bool


@dataclass(frozen=True)
class RemediationPolicyLoadInput:
    source: str | Path | Mapping[str, object]
    default_policy_name: str = "default"
    default_version: str = "1"


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError(f"{field}_IS_EMPTY")

    return value


def _version_text(value: object) -> str:
    """
    Policy versions may originate from YAML/JSON.

    Examples:
        version: 4       -> "4"
        version: 4.0     -> "4.0"
        version: "4"     -> "4"

    bool is deliberately rejected because bool is a subclass of int.
    """
    if isinstance(value, bool):
        raise TypeError("VERSION_MUST_BE_STRING")

    if isinstance(value, (str, int, float)):
        normalized = str(value).strip()

        if not normalized:
            raise ValueError("VERSION_IS_EMPTY")

        return normalized

    raise TypeError("VERSION_MUST_BE_STRING")


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field}_MUST_BE_BOOL")

    return value


def _optional_score(
    value: object,
    field: str,
) -> float | None:
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(
        value,
        (int, float),
    ):
        raise TypeError(f"{field}_MUST_BE_NUMERIC")

    value = float(value)

    if not 0 <= value <= 100:
        raise ValueError(f"{field}_OUT_OF_RANGE")

    return round(value, 2)


def _optional_non_negative_int(
    value: object,
    field: str,
) -> int | None:
    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(
        value,
        int,
    ):
        raise TypeError(f"{field}_MUST_BE_INTEGER")

    if value < 0:
        raise ValueError(f"{field}_MUST_BE_NON_NEGATIVE")

    return value


def _string_tuple(
    value: object,
    field: str,
) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{field}_MUST_BE_SEQUENCE")

    result: list[str] = []

    for item in value:
        result.append(
            _text(item, f"{field}_ITEM")
        )

    return tuple(dict.fromkeys(result))


def _mapping(
    source: Mapping[str, object],
) -> dict[str, object]:
    return dict(source)


def _parse_simple_yaml(text: str) -> dict[str, object]:
    """
    Minimal dependency-free YAML-like parser.

    Supported:
      key: value
      key:
        - item
        - item

    JSON is also accepted when the source begins with '{'.
    """

    stripped = text.strip()

    if not stripped:
        raise ValueError("POLICY_SOURCE_IS_EMPTY")

    if stripped.startswith("{"):
        import json

        parsed = json.loads(stripped)

        if not isinstance(parsed, dict):
            raise TypeError("POLICY_ROOT_MUST_BE_MAPPING")

        return parsed

    result: dict[str, object] = {}
    current_list_key: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("- "):
            if current_list_key is None:
                raise ValueError(
                    "INVALID_POLICY_LIST_ITEM"
                )

            existing = result.setdefault(
                current_list_key,
                [],
            )

            if not isinstance(existing, list):
                raise ValueError(
                    "POLICY_LIST_STRUCTURE_INVALID"
                )

            existing.append(
                line[2:].strip().strip("\"'")
            )
            continue

        if ":" not in line:
            raise ValueError(
                "INVALID_POLICY_LINE"
            )

        key, value = line.split(":", 1)

        key = key.strip()
        value = value.strip()

        if not key:
            raise ValueError(
                "POLICY_KEY_IS_EMPTY"
            )

        if not value:
            result[key] = []
            current_list_key = key
            continue

        current_list_key = None

        normalized = value.strip("\"'")
        lower = normalized.lower()

        if lower == "true":
            parsed_value: object = True
        elif lower == "false":
            parsed_value = False
        elif lower in {"null", "none"}:
            parsed_value = None
        else:
            try:
                parsed_value = int(normalized)
            except ValueError:
                try:
                    parsed_value = float(normalized)
                except ValueError:
                    parsed_value = normalized

        result[key] = parsed_value

    return result


def _load_source(
    source: str | Path | Mapping[str, object],
) -> tuple[dict[str, object], str]:

    if isinstance(source, Mapping):
        return _mapping(source), "<mapping>"

    # IMPORTANT:
    # Validate an empty string BEFORE converting it to Path.
    # Path("") becomes ".", which previously caused:
    # POLICY_SOURCE_NOT_FILE: .
    if isinstance(source, str):
        if not source.strip():
            raise ValueError(
                "POLICY_SOURCE_IS_EMPTY"
            )

        path = Path(source)

    elif isinstance(source, Path):
        path = source

    else:
        raise TypeError(
            "SOURCE_MUST_BE_PATH_STRING_OR_MAPPING"
        )

    if not path.exists():
        raise FileNotFoundError(
            f"POLICY_SOURCE_NOT_FOUND: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"POLICY_SOURCE_NOT_FILE: {path}"
        )

    try:
        text = path.read_text(
            encoding="utf-8"
        )
    except OSError as error:
        raise OSError(
            f"POLICY_SOURCE_READ_FAILED: {path}"
        ) from error

    return _parse_simple_yaml(text), str(path)


def _build_policy(
    data: Mapping[str, object],
    default_policy_name: str,
    default_version: str,
) -> RemediationPolicy:

    policy_name = _text(
        data.get(
            "policy_name",
            default_policy_name,
        ),
        "POLICY_NAME",
    )

    # IMPORTANT:
    # YAML parser converts "version: 4" to integer 4.
    # RemediationPolicy.version is str, therefore normalize it here.
    version = _version_text(
        data.get(
            "version",
            default_version,
        )
    )

    allowed_versions = _string_tuple(
        data.get("allowed_versions"),
        "ALLOWED_VERSIONS",
    )

    forbidden_versions = _string_tuple(
        data.get("forbidden_versions"),
        "FORBIDDEN_VERSIONS",
    )

    maximum_upgrade_distance = (
        _optional_non_negative_int(
            data.get("maximum_upgrade_distance"),
            "MAXIMUM_UPGRADE_DISTANCE",
        )
    )

    allow_major_upgrades = _bool(
        data.get(
            "allow_major_upgrades",
            False,
        ),
        "ALLOW_MAJOR_UPGRADES",
    )

    allow_production_dependencies = _bool(
        data.get(
            "allow_production_dependencies",
            True,
        ),
        "ALLOW_PRODUCTION_DEPENDENCIES",
    )

    allow_development_dependencies = _bool(
        data.get(
            "allow_development_dependencies",
            True,
        ),
        "ALLOW_DEVELOPMENT_DEPENDENCIES",
    )

    automated_remediation = _bool(
        data.get(
            "automated_remediation",
            False,
        ),
        "AUTOMATED_REMEDIATION",
    )

    manual_approval_required = _bool(
        data.get(
            "manual_approval_required",
            True,
        ),
        "MANUAL_APPROVAL_REQUIRED",
    )

    risk_threshold = _optional_score(
        data.get("risk_threshold"),
        "RISK_THRESHOLD",
    )

    change_scope = _text(
        data.get(
            "change_scope",
            "DEPENDENCY",
        ),
        "CHANGE_SCOPE",
    ).upper()

    dependency_policy = _text(
        data.get(
            "dependency_policy",
            "STANDARD",
        ),
        "DEPENDENCY_POLICY",
    ).upper()

    return RemediationPolicy(
        policy_name=policy_name,
        version=version,
        allowed_versions=allowed_versions,
        forbidden_versions=forbidden_versions,
        maximum_upgrade_distance=maximum_upgrade_distance,
        allow_major_upgrades=allow_major_upgrades,
        allow_production_dependencies=(
            allow_production_dependencies
        ),
        allow_development_dependencies=(
            allow_development_dependencies
        ),
        automated_remediation=automated_remediation,
        manual_approval_required=(
            manual_approval_required
        ),
        risk_threshold=risk_threshold,
        change_scope=change_scope,
        dependency_policy=dependency_policy,
    )


def load_remediation_policy(
    request: RemediationPolicyLoadInput,
) -> RemediationPolicyLoadingResult:

    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        RemediationPolicyLoadInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_REMEDIATION_POLICY_LOAD_INPUT"
        )

    default_policy_name = _text(
        request.default_policy_name,
        "DEFAULT_POLICY_NAME",
    )

    default_version = _text(
        request.default_version,
        "DEFAULT_VERSION",
    )

    data, source = _load_source(
        request.source
    )

    policy = _build_policy(
        data,
        default_policy_name,
        default_version,
    )

    return RemediationPolicyLoadingResult(
        policy=policy,
        source=source,
        loaded=True,
    )


# Public aliases.
remediation_policy_loading = load_remediation_policy
load_policy = load_remediation_policy


__all__ = [
    "RemediationPolicy",
    "RemediationPolicyLoadingResult",
    "RemediationPolicyLoadInput",
    "load_remediation_policy",
    "remediation_policy_loading",
    "load_policy",
]
