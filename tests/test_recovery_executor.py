import pytest

from sentinelshield.recovery_executor import (
    RecoveryExecutionResult,
    RecoveryExecutor,
    RecoveryOperation,
)
from sentinelshield.recovery_safety_gate import (
    RecoveryDecision,
    RecoveryGateResult,
)


def authorized():
    return RecoveryGateResult(
        project="demo",
        decision=RecoveryDecision.EXECUTE,
        allowed=True,
        reason="RECOVERY_AUTHORIZED",
    )


def denied():
    return RecoveryGateResult(
        project="demo",
        decision=RecoveryDecision.DENY,
        allowed=False,
        reason="RECOVERY_BLOCKED",
    )


def test_verify_existing_directory(tmp_path):
    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=tmp_path,
    )

    assert isinstance(result, RecoveryExecutionResult)
    assert result.executed is True
    assert result.success is True
    assert result.reason == "PATH_VERIFIED"


def test_verify_missing_directory(tmp_path):
    missing = tmp_path / "missing"

    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=missing,
    )

    assert result.executed is True
    assert result.success is False
    assert result.reason == "PATH_NOT_AVAILABLE"


def test_recreate_missing_directory(tmp_path):
    target = tmp_path / "recreated"

    assert not target.exists()

    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    assert result.executed is True
    assert result.success is True
    assert result.reason == "DIRECTORY_RECREATED"
    assert target.exists()
    assert target.is_dir()


def test_existing_directory_is_safe(tmp_path):
    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=tmp_path,
    )

    assert result.executed is True
    assert result.success is True
    assert result.reason == "DIRECTORY_ALREADY_EXISTS"


def test_file_target_is_rejected(tmp_path):
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")

    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    assert result.executed is False
    assert result.success is False
    assert result.reason == "TARGET_IS_NOT_DIRECTORY"


def test_denied_recovery_never_executes(tmp_path):
    target = tmp_path / "must_not_exist"

    result = RecoveryExecutor().execute(
        denied(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    assert result.executed is False
    assert result.success is False
    assert result.reason == "RECOVERY_NOT_AUTHORIZED"
    assert not target.exists()


def test_invalid_gate_type(tmp_path):
    with pytest.raises(TypeError):
        RecoveryExecutor().execute(
            object(),
            operation=RecoveryOperation.VERIFY_PATH,
            path=tmp_path,
        )


def test_invalid_operation_type(tmp_path):
    with pytest.raises(TypeError):
        RecoveryExecutor().execute(
            authorized(),
            operation="RECREATE_DIRECTORY",
            path=tmp_path,
        )


def test_invalid_path_type():
    with pytest.raises(TypeError):
        RecoveryExecutor().execute(
            authorized(),
            operation=RecoveryOperation.VERIFY_PATH,
            path=123,
        )


def test_result_is_immutable(tmp_path):
    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=tmp_path,
    )

    with pytest.raises(AttributeError):
        result.success = False


def test_project_name_preserved(tmp_path):
    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=tmp_path,
    )

    assert result.project == "demo"


def test_operation_preserved(tmp_path):
    result = RecoveryExecutor().execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=tmp_path,
    )

    assert result.operation == RecoveryOperation.VERIFY_PATH


def test_recreate_operation_is_idempotent(tmp_path):
    executor = RecoveryExecutor()
    target = tmp_path / "demo"

    first = executor.execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    second = executor.execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    assert first.success is True
    assert first.reason == "DIRECTORY_RECREATED"

    assert second.success is True
    assert second.reason == "DIRECTORY_ALREADY_EXISTS"


def test_verify_after_recreate(tmp_path):
    executor = RecoveryExecutor()
    target = tmp_path / "demo"

    executor.execute(
        authorized(),
        operation=RecoveryOperation.RECREATE_DIRECTORY,
        path=target,
    )

    result = executor.execute(
        authorized(),
        operation=RecoveryOperation.VERIFY_PATH,
        path=target,
    )

    assert result.success is True
    assert result.reason == "PATH_VERIFIED"
