import os
import sys

from sentinelshield.runtime import validate_python_runtime


def test_python_version_supported():
    result = validate_python_runtime()

    assert result["version_supported"] is True
    assert result["python_version"] >= (3, 11)


def test_python_executable_matches_current_runtime():
    result = validate_python_runtime()

    assert result["python_executable"] == sys.executable


def test_python_implementation():
    result = validate_python_runtime()

    assert result["python_implementation"] == sys.implementation.name


def test_python_path_is_valid():
    result = validate_python_runtime()

    assert isinstance(result["python_path"], list)
    assert result["python_path"]


def test_utf8_encoding():
    result = validate_python_runtime()

    assert result["filesystem_encoding"].lower() == "utf-8"
    assert result["default_encoding"].lower() == "utf-8"


def test_virtual_environment():
    result = validate_python_runtime()

    assert result["virtual_environment"] == os.environ.get("VIRTUAL_ENV")
