import os
import sys


MIN_PYTHON = (3, 11)


def validate_python_runtime() -> dict:
    version = sys.version_info

    return {
        "python_version": (
            version.major,
            version.minor,
            version.micro,
        ),
        "python_executable": sys.executable,
        "python_implementation": sys.implementation.name,
        "python_path": list(sys.path),
        "filesystem_encoding": sys.getfilesystemencoding(),
        "default_encoding": sys.getdefaultencoding(),
        "utf8_mode": sys.flags.utf8_mode,
        "virtual_environment": os.environ.get("VIRTUAL_ENV"),
        "version_supported": (version.major, version.minor) >= MIN_PYTHON,
    }
