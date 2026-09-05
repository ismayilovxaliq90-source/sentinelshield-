from pathlib import Path


class WorkspaceViolation(ValueError):
    """Raised when a path escapes the SentinelShield workspace."""


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()

    def contains(self, path: str | Path) -> bool:
        candidate = Path(path).expanduser().resolve()

        try:
            candidate.relative_to(self.root)
        except ValueError:
            return False

        return True

    def validate(self, path: str | Path) -> Path:
        candidate = Path(path).expanduser().resolve()

        if not self.contains(candidate):
            raise WorkspaceViolation(
                f"Path is outside SentinelShield workspace: {candidate}"
            )

        return candidate

    def path(self, relative_path: str | Path) -> Path:
        candidate = self.root / relative_path
        return self.validate(candidate)
