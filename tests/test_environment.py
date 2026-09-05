import os
import sys

from sentinelshield.environment import detect_environment


def test_environment_detection():
    result = detect_environment()

    assert isinstance(result, dict)

    assert result["os"]
    assert result["architecture"]
    assert result["python_version"]
    assert result["python_executable"]
    assert result["python_implementation"]


def test_python_executable_matches_current_runtime():
    result = detect_environment()

    assert result["python_executable"] == sys.executable


def test_virtual_environment():
    result = detect_environment()

    assert result["virtual_environment"] == os.environ.get("VIRTUAL_ENV")
