from pathlib import Path


class ProjectPathViolation(Exception):
    """Raised when a project path violates SentinelShield path policy."""


class ProjectPathValidator:
    """
    Validates that a project path exists, is a directory,
    and remains inside the configured workspace.
    """

    def __init__(self, workspace_root):
        try:
            self.workspace_root = Path(workspace_root).resolve(strict=True)
        except FileNotFoundError as exc:
            raise ProjectPathViolation(
                f"Workspace does not exist: {workspace_root}"
            ) from exc

        if not self.workspace_root.is_dir():
            raise ProjectPathViolation(
                f"Workspace is not a directory: {self.workspace_root}"
            )

    def validate(self, project_path):
        candidate = Path(project_path)

        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ProjectPathViolation(
                f"Project path does not exist: {project_path}"
            ) from exc

        if not resolved.is_dir():
            raise ProjectPathViolation(
                f"Project path is not a directory: {resolved}"
            )

        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ProjectPathViolation(
                f"Project path is outside workspace: {resolved}"
            ) from exc

        return resolved
