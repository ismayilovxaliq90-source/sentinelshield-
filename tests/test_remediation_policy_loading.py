import json

import pytest

from sentinelshield.remediation_policy_loading import (
    RemediationPolicy,
    RemediationPolicyLoadInput,
    RemediationPolicyLoadingResult,
    load_policy,
    load_remediation_policy,
    remediation_policy_loading,
)


def test_load_policy_from_mapping():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={
                "policy_name": "security",
                "version": "2",
                "allowed_versions": [
                    "1.2.3",
                    "1.3.0",
                ],
                "forbidden_versions": [
                    "3.0.0",
                ],
                "maximum_upgrade_distance": 10,
                "allow_major_upgrades": False,
                "allow_production_dependencies": True,
                "allow_development_dependencies": True,
                "automated_remediation": True,
                "manual_approval_required": True,
                "risk_threshold": 50,
                "change_scope": "dependency",
                "dependency_policy": "strict",
            }
        )
    )

    assert isinstance(
        result,
        RemediationPolicyLoadingResult,
    )
    assert result.loaded is True
    assert result.policy.policy_name == "security"
    assert result.policy.version == "2"
    assert result.policy.allowed_versions == (
        "1.2.3",
        "1.3.0",
    )
    assert result.policy.forbidden_versions == (
        "3.0.0",
    )
    assert result.policy.maximum_upgrade_distance == 10
    assert result.policy.allow_major_upgrades is False
    assert result.policy.risk_threshold == 50.0
    assert result.policy.change_scope == "DEPENDENCY"
    assert result.policy.dependency_policy == "STRICT"


def test_defaults_are_applied():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={}
        )
    )

    policy = result.policy

    assert policy.policy_name == "default"
    assert policy.version == "1"
    assert policy.allowed_versions == ()
    assert policy.forbidden_versions == ()
    assert policy.maximum_upgrade_distance is None
    assert policy.allow_major_upgrades is False
    assert policy.allow_production_dependencies is True
    assert policy.allow_development_dependencies is True
    assert policy.automated_remediation is False
    assert policy.manual_approval_required is True
    assert policy.risk_threshold is None
    assert policy.change_scope == "DEPENDENCY"
    assert policy.dependency_policy == "STANDARD"


def test_duplicate_version_entries_are_removed():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={
                "allowed_versions": [
                    "1.0.0",
                    "1.0.0",
                    "1.1.0",
                ]
            }
        )
    )

    assert result.policy.allowed_versions == (
        "1.0.0",
        "1.1.0",
    )


def test_load_json_file(tmp_path):
    path = tmp_path / "policy.json"

    path.write_text(
        json.dumps(
            {
                "policy_name": "json-policy",
                "version": "3",
                "risk_threshold": 75,
                "allow_major_upgrades": True,
            }
        ),
        encoding="utf-8",
    )

    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source=path
        )
    )

    assert result.source == str(path)
    assert result.loaded is True
    assert result.policy.policy_name == "json-policy"
    assert result.policy.risk_threshold == 75.0
    assert result.policy.allow_major_upgrades is True


def test_load_simple_yaml_file(tmp_path):
    path = tmp_path / "policy.yaml"

    path.write_text(
        """
policy_name: production
version: 4
maximum_upgrade_distance: 5
allow_major_upgrades: false
allow_production_dependencies: true
risk_threshold: 40
change_scope: dependency
dependency_policy: strict
allowed_versions:
  - 1.2.0
  - 1.3.0
forbidden_versions:
  - 2.0.0
""".strip(),
        encoding="utf-8",
    )

    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source=path
        )
    )

    assert result.policy.policy_name == "production"
    assert result.policy.version == "4"
    assert result.policy.maximum_upgrade_distance == 5
    assert result.policy.allowed_versions == (
        "1.2.0",
        "1.3.0",
    )
    assert result.policy.forbidden_versions == (
        "2.0.0",
    )
    assert result.policy.risk_threshold == 40.0


def test_path_string_is_supported(tmp_path):
    path = tmp_path / "policy.json"

    path.write_text(
        '{"policy_name": "file-policy"}',
        encoding="utf-8",
    )

    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source=str(path)
        )
    )

    assert result.policy.policy_name == "file-policy"


def test_missing_file_rejected(tmp_path):
    path = tmp_path / "missing.json"

    with pytest.raises(
        FileNotFoundError,
        match="POLICY_SOURCE_NOT_FOUND",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source=path
            )
        )


def test_directory_rejected(tmp_path):
    with pytest.raises(
        ValueError,
        match="POLICY_SOURCE_NOT_FILE",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source=tmp_path
            )
        )


def test_empty_source_rejected():
    with pytest.raises(
        ValueError,
        match="POLICY_SOURCE_IS_EMPTY",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source=""
            )
        )


def test_invalid_source_type():
    with pytest.raises(
        TypeError,
        match="SOURCE_MUST_BE_PATH_STRING_OR_MAPPING",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source=123
            )
        )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        load_remediation_policy(None)


def test_invalid_request_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_REMEDIATION_POLICY_LOAD_INPUT",
    ):
        load_remediation_policy({})


def test_invalid_policy_name():
    with pytest.raises(
        ValueError,
        match="POLICY_NAME_IS_EMPTY",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "policy_name": ""
                }
            )
        )


def test_invalid_boolean():
    with pytest.raises(
        TypeError,
        match="ALLOW_MAJOR_UPGRADES_MUST_BE_BOOL",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "allow_major_upgrades": 1
                }
            )
        )


def test_invalid_risk_threshold():
    with pytest.raises(
        ValueError,
        match="RISK_THRESHOLD_OUT_OF_RANGE",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "risk_threshold": 101
                }
            )
        )


def test_invalid_upgrade_distance():
    with pytest.raises(
        ValueError,
        match="MAXIMUM_UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "maximum_upgrade_distance": -1
                }
            )
        )


def test_invalid_allowed_versions():
    with pytest.raises(
        TypeError,
        match="ALLOWED_VERSIONS_MUST_BE_SEQUENCE",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "allowed_versions": 123
                }
            )
        )


def test_invalid_version_item():
    with pytest.raises(
        TypeError,
        match="ALLOWED_VERSIONS_ITEM_MUST_BE_STRING",
    ):
        load_remediation_policy(
            RemediationPolicyLoadInput(
                source={
                    "allowed_versions": [123]
                }
            )
        )


def test_policy_is_immutable():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={}
        )
    )

    with pytest.raises(
        AttributeError
    ):
        result.policy.policy_name = "changed"


def test_aliases():
    assert (
        remediation_policy_loading
        is load_remediation_policy
    )
    assert load_policy is load_remediation_policy


def test_custom_defaults():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={},
            default_policy_name="enterprise",
            default_version="7",
        )
    )

    assert result.policy.policy_name == "enterprise"
    assert result.policy.version == "7"


def test_boolean_policy_fields():
    result = load_remediation_policy(
        RemediationPolicyLoadInput(
            source={
                "allow_major_upgrades": True,
                "allow_production_dependencies": False,
                "allow_development_dependencies": False,
                "automated_remediation": True,
                "manual_approval_required": False,
            }
        )
    )

    assert result.policy.allow_major_upgrades is True
    assert (
        result.policy.allow_production_dependencies
        is False
    )
    assert (
        result.policy.allow_development_dependencies
        is False
    )
    assert result.policy.automated_remediation is True
    assert result.policy.manual_approval_required is False


def test_deterministic_mapping_load():
    request = RemediationPolicyLoadInput(
        source={
            "policy_name": "deterministic",
            "version": "1",
            "allowed_versions": [
                "1.0.0",
                "1.1.0",
            ],
            "risk_threshold": 50,
        }
    )

    assert (
        load_remediation_policy(request)
        == load_remediation_policy(request)
    )
