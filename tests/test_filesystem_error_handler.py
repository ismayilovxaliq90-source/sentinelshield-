from pathlib import Path

from sentinelshield.filesystem_error_handler import (
    FilesystemErrorHandler,
    FilesystemOperationResult,
    safe_exists,
    safe_is_dir,
    safe_is_file,
)


def test_successful_operation():
    handler = FilesystemErrorHandler()

    result = handler.execute(lambda: "OK")

    assert isinstance(
        result,
        FilesystemOperationResult,
    )
    assert result.success is True
    assert result.value == "OK"
    assert result.error_type is None
    assert result.reason == (
        "FILESYSTEM_OPERATION_SUCCESS"
    )


def test_permission_error_is_handled():
    handler = FilesystemErrorHandler()

    def operation():
        raise PermissionError("denied")

    result = handler.execute(operation)

    assert result.success is False
    assert result.value is None
    assert result.error_type == "PermissionError"
    assert result.reason == (
        "FILESYSTEM_PERMISSION_DENIED"
    )


def test_os_error_is_handled():
    handler = FilesystemErrorHandler()

    def operation():
        raise OSError("filesystem failure")

    result = handler.execute(operation)

    assert result.success is False
    assert result.value is None
    assert result.error_type == "OSError"
    assert result.reason == "FILESYSTEM_OS_ERROR"


def test_runtime_error_is_handled():
    handler = FilesystemErrorHandler()

    def operation():
        raise RuntimeError("runtime failure")

    result = handler.execute(operation)

    assert result.success is False
    assert result.value is None
    assert result.error_type == "RuntimeError"
    assert result.reason == (
        "FILESYSTEM_RUNTIME_ERROR"
    )


def test_successful_exists(tmp_path):
    result = safe_exists(tmp_path)

    assert result.success is True
    assert result.value is True


def test_nonexistent_exists(tmp_path):
    target = tmp_path / "missing"

    result = safe_exists(target)

    assert result.success is True
    assert result.value is False


def test_successful_is_dir(tmp_path):
    result = safe_is_dir(tmp_path)

    assert result.success is True
    assert result.value is True


def test_successful_is_file(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("test", encoding="utf-8")

    result = safe_is_file(file_path)

    assert result.success is True
    assert result.value is True


def test_filesystem_helper_does_not_create_path(tmp_path):
    target = tmp_path / "does-not-exist"

    result = safe_exists(target)

    assert result.success is True
    assert result.value is False
    assert not target.exists()


def test_exception_does_not_escape():
    handler = FilesystemErrorHandler()

    def operation():
        raise PermissionError("blocked")

    try:
        result = handler.execute(operation)
    except Exception as exc:
        raise AssertionError(
            f"Filesystem exception escaped: {exc}"
        )

    assert result.success is False
