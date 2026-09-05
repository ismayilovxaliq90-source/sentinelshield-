import pytest

from sentinelshield.disk_log_protection import (
    DiskLogProtectionError,
    DiskLogRunawayProtection,
    SizeCheck,
)


def test_default_limits_are_positive():
    protection = DiskLogRunawayProtection()

    assert protection.file_limit_bytes > 0
    assert protection.log_limit_bytes > 0


def test_custom_limits_are_accepted():
    protection = DiskLogRunawayProtection(
        file_limit_bytes=100,
        log_limit_bytes=50,
    )

    assert protection.file_limit_bytes == 100
    assert protection.log_limit_bytes == 50


def test_zero_file_limit_is_rejected():
    with pytest.raises(ValueError):
        DiskLogRunawayProtection(
            file_limit_bytes=0
        )


def test_negative_log_limit_is_rejected():
    with pytest.raises(ValueError):
        DiskLogRunawayProtection(
            log_limit_bytes=-1
        )


def test_non_integer_file_limit_is_rejected():
    with pytest.raises(TypeError):
        DiskLogRunawayProtection(
            file_limit_bytes="100"
        )


def test_boolean_log_limit_is_rejected():
    with pytest.raises(TypeError):
        DiskLogRunawayProtection(
            log_limit_bytes=True
        )


def test_existing_file_size_is_read(tmp_path):
    target = tmp_path / "test.txt"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection()

    assert protection.size_bytes(target) == 5


def test_missing_file_is_reported(tmp_path):
    target = tmp_path / "missing.log"

    protection = DiskLogRunawayProtection()

    with pytest.raises(DiskLogProtectionError):
        protection.size_bytes(target)


def test_file_within_limit_is_allowed(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=10,
    )

    result = protection.check_file(target)

    assert isinstance(result, SizeCheck)
    assert result.size_bytes == 5
    assert result.limit_bytes == 10
    assert result.allowed is True


def test_file_at_exact_limit_is_allowed(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=5,
    )

    result = protection.check_file(target)

    assert result.allowed is True


def test_file_above_limit_is_blocked(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=5,
    )

    result = protection.check_file(target)

    assert result.allowed is False


def test_require_file_safe_blocks_excessive_file(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=5,
    )

    with pytest.raises(DiskLogProtectionError):
        protection.require_file_safe(target)


def test_is_file_safe_returns_true_when_allowed(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=10,
    )

    assert protection.is_file_safe(target) is True


def test_is_file_safe_returns_false_when_blocked(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=5,
    )

    assert protection.is_file_safe(target) is False


def test_log_within_limit_is_allowed(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=10,
    )

    result = protection.check_log(target)

    assert result.allowed is True
    assert result.size_bytes == 5


def test_log_at_exact_limit_is_allowed(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=5,
    )

    result = protection.check_log(target)

    assert result.allowed is True


def test_log_above_limit_is_blocked(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=5,
    )

    result = protection.check_log(target)

    assert result.allowed is False


def test_require_log_safe_blocks_excessive_log(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=5,
    )

    with pytest.raises(DiskLogProtectionError):
        protection.require_log_safe(target)


def test_is_log_safe_returns_true_when_allowed(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=10,
    )

    assert protection.is_log_safe(target) is True


def test_is_log_safe_returns_false_when_blocked(tmp_path):
    target = tmp_path / "sentinel.log"
    target.write_bytes(b"123456")

    protection = DiskLogRunawayProtection(
        log_limit_bytes=5,
    )

    assert protection.is_log_safe(target) is False


def test_protection_does_not_modify_file(tmp_path):
    target = tmp_path / "sentinel.log"
    original = b"original-content"

    target.write_bytes(original)

    protection = DiskLogRunawayProtection(
        log_limit_bytes=5,
    )

    assert protection.is_log_safe(target) is False
    assert target.read_bytes() == original


def test_size_check_is_deterministic(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"12345")

    protection = DiskLogRunawayProtection(
        file_limit_bytes=10,
    )

    first = protection.check_file(target)
    second = protection.check_file(target)

    assert first == second
