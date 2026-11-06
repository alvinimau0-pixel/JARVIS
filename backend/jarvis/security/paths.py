"""Workspace path containment.

All filesystem targets are resolved (following symlinks) and must stay inside an approved
workspace root. Absolute paths, drive letters, UNC paths and NUL bytes are rejected outright.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

_DRIVE = re.compile(r"^[A-Za-z]:")


class WorkspaceViolation(ValueError):
    """Raised when a path would escape its workspace."""


def resolve_in_workspace(root: Path, relative: str) -> Path:
    if "\x00" in relative:
        raise WorkspaceViolation("path contains NUL byte")
    if relative.startswith(("\\\\", "//")) or _DRIVE.match(relative):
        raise WorkspaceViolation("UNC or drive-qualified paths are not allowed")
    if PurePosixPath(relative).is_absolute() or PureWindowsPath(relative).is_absolute():
        raise WorkspaceViolation("absolute paths are not allowed")
    if relative.startswith("\\"):
        raise WorkspaceViolation("rooted paths are not allowed")

    root_real = Path(os.path.realpath(root))
    candidate = Path(os.path.realpath(root_real / relative))
    try:
        common = os.path.commonpath([root_real, candidate])
    except ValueError as exc:  # different drives on Windows
        raise WorkspaceViolation("path is outside the workspace") from exc
    if os.path.normcase(common) != os.path.normcase(str(root_real)):
        raise WorkspaceViolation("path is outside the workspace")
    return candidate


def find_workspace(workspaces: list[Path], name: str) -> Path:
    """Look up an approved workspace by its directory name."""
    for ws in workspaces:
        if ws.name == name:
            return Path(os.path.realpath(ws))
    raise WorkspaceViolation(f"'{name}' is not an approved workspace")
