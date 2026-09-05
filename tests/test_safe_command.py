import sys

import pytest

from sentinelshield.safe_command import (
    CommandResult,
    SafeCommandError,
    SafeCommandExecutor,
)


def test_default_timeout_is_positive():
    executor = SafeCommandExecutor()
    assert executor.timeout > 0


def test_zero_timeout_is_rejected():
    with pytest.raises(ValueError):
        SafeCommandExecutor(timeout=0)


def test_negative_timeout_is_rejected():
    with pytest.raises(ValueError):
        SafeCommandExecutor(timeout=-1)


def test_string_command_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(TypeError):
        executor.validate_command("echo hello")


def test_empty_command_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(ValueError):
        executor.validate_command([])


def test_empty_argument_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(ValueError):
        executor.validate_command(["echo", ""])


def test_non_string_argument_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(TypeError):
        executor.validate_command(["echo", 123])


def test_command_is_normalized_to_tuple():
    executor = SafeCommandExecutor()

    assert executor.validate_command(
        ["echo", "hello"]
    ) == ("echo", "hello")


def test_successful_command_execution():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "print('SAFE')",
    ])

    assert isinstance(result, CommandResult)
    assert result.return_code == 0
    assert result.stdout.strip() == "SAFE"
    assert result.timed_out is False


def test_failed_command_return_code_is_preserved():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "raise SystemExit(7)",
    ])

    assert result.return_code == 7
    assert result.timed_out is False


def test_stderr_is_captured():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "import sys; sys.stderr.write('ERR')",
    ])

    assert result.return_code == 0
    assert result.stderr == "ERR"


def test_stdout_is_captured_separately():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "print('OUT')",
    ])

    assert result.stdout.strip() == "OUT"
    assert result.stderr == ""


def test_extra_environment_is_controlled():
    executor = SafeCommandExecutor()

    result = executor.execute(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['SENTINEL_TEST'])",
        ],
        extra_env={
            "SENTINEL_TEST": "SAFE_VALUE"
        },
    )

    assert result.return_code == 0
    assert result.stdout.strip() == "SAFE_VALUE"


def test_custom_environment_keeps_path():
    executor = SafeCommandExecutor()

    environment = executor.build_environment({
        "SENTINEL_TEST": "1"
    })

    assert "PATH" in environment
    assert environment["SENTINEL_TEST"] == "1"


def test_invalid_environment_key_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(TypeError):
        executor.build_environment({123: "value"})


def test_invalid_environment_value_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(TypeError):
        executor.build_environment({"TEST": 123})


def test_empty_environment_key_is_rejected():
    executor = SafeCommandExecutor()

    with pytest.raises(ValueError):
        executor.build_environment({"": "value"})


def test_timeout_is_reported():
    executor = SafeCommandExecutor(timeout=0.05)

    result = executor.execute([
        sys.executable,
        "-c",
        "import time; time.sleep(1)",
    ])

    assert result.timed_out is True
    assert result.return_code == -1


def test_custom_timeout_is_supported():
    executor = SafeCommandExecutor(timeout=1)

    result = executor.execute(
        [
            sys.executable,
            "-c",
            "print('OK')",
        ],
        timeout=2,
    )

    assert result.return_code == 0
    assert result.timed_out is False


def test_cwd_is_supported(tmp_path):
    executor = SafeCommandExecutor()

    result = executor.execute(
        [
            sys.executable,
            "-c",
            "import os; print(os.getcwd())",
        ],
        cwd=str(tmp_path),
    )

    assert result.return_code == 0
    assert result.stdout.strip() == str(tmp_path)


def test_success_helper_accepts_success_result():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "pass",
    ])

    assert executor.is_successful(result) is True


def test_success_helper_rejects_failed_result():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "raise SystemExit(1)",
    ])

    assert executor.is_successful(result) is False


def test_success_helper_rejects_timeout():
    executor = SafeCommandExecutor(timeout=0.05)

    result = executor.execute([
        sys.executable,
        "-c",
        "import time; time.sleep(1)",
    ])

    assert executor.is_successful(result) is False


def test_command_result_preserves_command():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "pass",
    ])

    assert result.command[0] == sys.executable
    assert result.command[1] == "-c"


def test_shell_metacharacters_are_not_interpreted():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "import sys; print(sys.argv[1])",
        "hello; echo SHOULD_NOT_RUN",
    ])

    assert result.return_code == 0
    assert result.stdout.strip() == "hello; echo SHOULD_NOT_RUN"


def test_missing_executable_is_reported():
    executor = SafeCommandExecutor()

    with pytest.raises(SafeCommandError):
        executor.execute([
            "definitely-not-a-real-command"
        ])


def test_execution_does_not_raise_on_nonzero_return():
    executor = SafeCommandExecutor()

    result = executor.execute([
        sys.executable,
        "-c",
        "raise SystemExit(3)",
    ])

    assert result.return_code == 3
    assert result.timed_out is False


def test_safe_execution_is_deterministic():
    executor = SafeCommandExecutor()

    first = executor.execute([
        sys.executable,
        "-c",
        "print('DETERMINISTIC')",
    ])

    second = executor.execute([
        sys.executable,
        "-c",
        "print('DETERMINISTIC')",
    ])

    assert first.return_code == second.return_code
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr
