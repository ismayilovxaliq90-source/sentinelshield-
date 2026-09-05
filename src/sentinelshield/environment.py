import os
import platform
import sys


def detect_environment() -> dict:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "python_implementation": platform.python_implementation(),
        "virtual_environment": os.environ.get("VIRTUAL_ENV"),
    }

