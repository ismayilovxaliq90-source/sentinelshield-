import math

import pytest

from sentinelshield.remediation_dry_run import (
    RemediationDryRunError,
    RemediationDryRunPolicy,
    prepare_remediation_dry_run,
    require_remediation_dry_run,
)


def test_valid_command_is_only_validated():
    result = prepare_remediation_dry_run(
        ("package-manager", "update", "package-a"),
        working_directory="/tmp/remediation-workspace",
    )

    assert result.valid is True
    assert result.executable == "package-manager"
    assert result.arguments == ("update", "package-a")
    assert result.executed is False
    assert result.filesystem_modified is False
    assert result.reason == "DRY_RUN_VALIDATED_WITHOUT_EXECUTION"


def test_string_command_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            "package-manager update",
            working_directory="/tmp/workspace",
        )


def test_empty_command_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            (),
            working_directory="/tmp/workspace",
        )


@pytest.mark.parametrize(
    "token",
    [";", "&&", "||", "|", "`", "$(", "${", ">", "<", "\n", "\r"],
)
def test_shell_tokens_are_rejected(token):
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", f"safe{token}unsafe"),
            working_directory="/tmp/workspace",
        )


def test_executable_cannot_contain_whitespace():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("package manager", "update"),
            working_directory="/tmp/workspace",
        )


def test_control_character_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "safe\x00value"),
            working_directory="/tmp/workspace",
        )


def test_argument_count_limit_is_enforced():
    policy = RemediationDryRunPolicy(
        max_arguments=2,
    )

    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "one", "two"),
            working_directory="/tmp/workspace",
            policy=policy,
        )


def test_argument_length_limit_is_enforced():
    policy = RemediationDryRunPolicy(
        max_argument_length=4,
    )

    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "12345"),
            working_directory="/tmp/workspace",
            policy=policy,
        )


def test_environment_keys_are_recorded_without_values():
    result = prepare_remediation_dry_run(
        ("tool", "update"),
        working_directory="/tmp/workspace",
        environment={
            "CI": "true",
            "TOKEN": "secret-value",
        },
    )

    assert result.environment_keys == ("CI", "TOKEN")
    assert "secret-value" not in str(result.to_dict())


def test_environment_key_with_equals_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="/tmp/workspace",
            environment={"BAD=KEY": "value"},
        )


def test_empty_working_directory_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="",
        )


def test_path_object_is_accepted():
    result = prepare_remediation_dry_run(
        ("tool", "update"),
        working_directory="/tmp/workspace",
    )

    assert result.working_directory == "/tmp/workspace"


def test_timeout_policy_is_validated():
    policy = RemediationDryRunPolicy(
        timeout_seconds=30,
        max_timeout_seconds=60,
    )

    result = prepare_remediation_dry_run(
        ("tool", "update"),
        working_directory="/tmp/workspace",
        policy=policy,
    )

    assert result.timeout_seconds == 30.0
    assert math.isfinite(result.timeout_seconds)


def test_timeout_above_maximum_is_rejected():
    policy = RemediationDryRunPolicy(
        timeout_seconds=61,
        max_timeout_seconds=60,
    )

    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="/tmp/workspace",
            policy=policy,
        )


@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("inf"), float("nan")],
)
def test_invalid_timeout_is_rejected(timeout):
    policy = RemediationDryRunPolicy(
        timeout_seconds=timeout,
        max_timeout_seconds=600,
    )

    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="/tmp/workspace",
            policy=policy,
        )


def test_shell_policy_cannot_be_enabled():
    policy = RemediationDryRunPolicy(
        allow_shell=True,
    )

    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="/tmp/workspace",
            policy=policy,
        )


def test_invalid_policy_type_is_rejected():
    with pytest.raises(RemediationDryRunError):
        prepare_remediation_dry_run(
            ("tool", "update"),
            working_directory="/tmp/workspace",
            policy=object(),
        )


def test_require_returns_valid_result():
    result = require_remediation_dry_run(
        ("tool", "check"),
        working_directory="/tmp/workspace",
    )

    assert result.valid is True
    assert result.executed is False


def test_to_dict_is_safe_for_environment_secrets():
    result = prepare_remediation_dry_run(
        ("tool", "check"),
        working_directory="/tmp/workspace",
        environment={
            "SECRET": "do-not-leak-this-value",
        },
    )

    data = result.to_dict()

    assert data["environment_keys"] == ["SECRET"]
    assert "do-not-leak-this-value" not in str(data)


def test_dry_run_result_explicitly_reports_no_execution():
    result = prepare_remediation_dry_run(
        ("tool", "check"),
        working_directory="/tmp/workspace",
    )

    assert result.executed is False
    assert result.filesystem_modified is False
