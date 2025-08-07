import logging
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import ClassVar, Final, List, Optional, Union, Sequence

# It is assumed that these interfaces are implemented securely.
# The Shell implementation, in particular, MUST NOT use shell=True or string concatenation.
from ._interfaces import FileSystem, Shell

_logger = logging.getLogger(__name__)


# ── Enums & Data Structures ────────────────────────────────────────────────


class ActionStatus(Enum):
    """Represents the outcome of an action in a deterministic way."""

    OK = auto()
    FAIL_PRECONDITION = auto()  # E.g., validation failed before execution
    FAIL_EXECUTION = auto()  # Error during the core operation (I/O, command)
    FAIL_TIMEOUT = auto()  # Command timed out
    FAIL_UNAUTHORIZED = auto()  # E.g., path traversal, non-whitelisted command


@dataclass(frozen=True)
class ActionResult:
    """An immutable, thread-safe result object for any action."""

    status: ActionStatus
    message: str = ""
    output: Optional[Union[str, bytes]] = None


class ActionType(Enum):
    """Defines the category of an action."""

    COMMAND = "COMMAND"
    CREATE_DIRECTORY = "CREATE_DIRECTORY"
    CREATE_FILE = "CREATE_FILE"
    CHECK_FILE = "CHECK_FILE"
    CHECK_DIRECTORY = "CHECK_DIRECTORY"


# ── Base Action & Path Security Mixin ──────────────────────────────────────


class Action(ABC):
    """
    Abstract Base Class for a self-contained, stateless, and observable build action.
    """

    # ClassVars ensure these are defined by subclasses, not instance variables
    type: ClassVar[ActionType]
    description: str

    @abstractmethod
    def run(self) -> ActionResult:
        """
        Executes the action.

        Returns:
            ActionResult: An immutable object describing the outcome.
        """

    def __str__(self) -> str:
        return f"[{self.type.name}] {self.description}"


class SecurePathMixin:
    """
    Mixin to resolve and validate paths against traversal, symlinks, and TOCTOU.

    This mixin relies on an injected FileSystem abstraction for testability.
    """

    fs: FileSystem
    allowed_base: Optional[Path]

    def secure_resolve(self, raw_path: Path) -> Path:
        """
        Resolves a path while enforcing security constraints.

        Raises:
            ValueError: On any security violation (path traversal, symlinks).
        """
        # 1. Resolve path without requiring existence on the filesystem.
        # This canonicalizes paths like '.', '..', and '//'.
        resolved_path = raw_path.resolve(strict=False)

        # 2. Prevent path traversal attacks. This is safer than string comparison.
        if self.allowed_base and not resolved_path.is_relative_to(self.allowed_base):
            raise ValueError(
                f"Path escape attempt: '{resolved_path}' is not under '{self.allowed_base}'"
            )

        # 3. Check for symlinks in the resolved path's parents.
        # This must be done before any filesystem access.
        for part in resolved_path.parents:
            if self.fs.is_symlink(part):
                raise ValueError(f"Symlink detected in path component: '{part}'")

        # Note: The final component of the path is checked during the atomic operation
        # (e.g., os.open with O_NOFOLLOW) to mitigate TOCTOU vulnerabilities.
        return resolved_path


# ── Filesystem Actions ────────────────────────────────────────────────────


class CreateDirectoryAction(Action, SecurePathMixin):
    type = ActionType.CREATE_DIRECTORY

    def __init__(self, path: Path, fs: FileSystem, allowed_base: Path, exist_ok: bool = False):
        self.fs = fs
        self.allowed_base = allowed_base.resolve()
        self.raw_path = path
        self.exist_ok = exist_ok
        self.description = f"Create directory {path}"

    def run(self) -> ActionResult:
        try:
            safe_path = self.secure_resolve(self.raw_path)
            # The is_symlink check for the final component
            if self.fs.is_symlink(safe_path):
                raise ValueError(f"Path cannot be a symlink: '{safe_path}'")

            self.fs.mkdir(safe_path, parents=True, exist_ok=self.exist_ok)
            _logger.info("Successfully created directory: %s", safe_path)
            return ActionResult(status=ActionStatus.OK)
        except (ValueError, PermissionError) as e:
            msg = f"Unauthorized directory creation: {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_UNAUTHORIZED, message=msg)
        except (IOError, OSError) as e:
            msg = f"Failed to create directory '{self.raw_path}': {e}"
            _logger.error(msg)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg)


class CreateFileAction(Action, SecurePathMixin):
    type = ActionType.CREATE_FILE

    def __init__(self, path: Path, content: str, fs: FileSystem, allowed_base: Path):
        self.fs = fs
        self.allowed_base = allowed_base.resolve()
        self.raw_path = path
        self.content = content
        self.description = f"Create file {path}"

    def run(self) -> ActionResult:
        try:
            safe_path = self.secure_resolve(self.raw_path)
            if self.fs.is_symlink(safe_path):
                raise ValueError(f"Path cannot be a symlink: '{safe_path}'")

            # Ensure parent exists securely before writing
            parent_dir = safe_path.parent
            if not self.fs.is_dir(parent_dir):
                self.fs.mkdir(parent_dir, parents=True, exist_ok=True)

            self.fs.write_file_atomic(safe_path, self.content)
            _logger.info("Successfully created file: %s", safe_path)
            return ActionResult(status=ActionStatus.OK)
        except (ValueError, PermissionError) as e:
            msg = f"Unauthorized file creation: {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_UNAUTHORIZED, message=msg)
        except (IOError, OSError) as e:
            msg = f"Failed to create file '{self.raw_path}': {e}"
            _logger.error(msg)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg)


class CheckFileAction(Action, SecurePathMixin):
    """Checks for a regular file atomically, avoiding TOCTOU."""

    type = ActionType.CHECK_FILE

    def __init__(self, path: Path, fs: FileSystem, allowed_base: Path):
        self.fs = fs
        self.allowed_base = allowed_base.resolve()
        self.raw_path = path
        self.description = f"Check file {path}"

    def run(self) -> ActionResult:
        try:
            safe_path = self.secure_resolve(self.raw_path)
            # ATOMIC CHECK: os.open is the safest way to check for a file's existence
            # and type without a race condition. O_NOFOLLOW prevents opening symlinks.
            # We don't need fs.is_file() beforehand (which would be TOCTOU).
            fd = self.fs.open(str(safe_path), os.O_RDONLY | os.O_NOFOLLOW)
            self.fs.close(fd)
            _logger.info("Check OK: '%s' is a regular file.", safe_path)
            return ActionResult(status=ActionStatus.OK)
        except (ValueError, PermissionError) as e:
            msg = f"Unauthorized file access check: {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_UNAUTHORIZED, message=msg)
        except (IsADirectoryError, FileNotFoundError, OSError) as e:
            msg = f"File check failed for '{self.raw_path}': {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg)


class CheckDirectoryAction(Action, SecurePathMixin):
    """Checks for a directory atomically, avoiding TOCTOU."""

    type = ActionType.CHECK_DIRECTORY

    def __init__(self, path: Path, fs: FileSystem, allowed_base: Path):
        self.fs = fs
        self.allowed_base = allowed_base.resolve()
        self.raw_path = path
        self.description = f"Check directory {path}"

    def run(self) -> ActionResult:
        try:
            safe_path = self.secure_resolve(self.raw_path)
            # ATOMIC CHECK: O_DIRECTORY flag ensures the path is a directory.
            # O_NOFOLLOW prevents opening symlinks.
            fd = self.fs.open(str(safe_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fs.close(fd)
            _logger.info("Check OK: '%s' is a directory.", safe_path)
            return ActionResult(status=ActionStatus.OK)
        except (ValueError, PermissionError) as e:
            msg = f"Unauthorized directory access check: {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_UNAUTHORIZED, message=msg)
        except (NotADirectoryError, FileNotFoundError, OSError) as e:
            msg = f"Directory check failed for '{self.raw_path}': {e}"
            _logger.warning(msg)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg)


# ── Command Action ────────────────────────────────────────────────────────


class CommandAction(Action):
    """
    Runs a shell command with strict validation and resource limits.
    """

    type = ActionType.COMMAND
    # Use Final for immutable configuration
    MAX_ARGS: Final[int] = 20
    DEFAULT_TIMEOUT: Final[float] = 30.0

    def __init__(
        self,
        cmd: Sequence[str],
        shell: Shell,
        allowed_whitelist: Sequence[str],
        capture_output: bool = True,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ):
        self.shell = shell
        self.cmd = cmd
        self.allowed_whitelist = allowed_whitelist
        self.capture_output = capture_output
        self.timeout = timeout
        self.description = f"Run command {' '.join(cmd)}"

    def _validate_preconditions(self) -> Optional[ActionResult]:
        """Performs checks before attempting to execute the command."""
        if not self.cmd:
            return ActionResult(ActionStatus.FAIL_PRECONDITION, "Command cannot be empty.")
        if len(self.cmd) > self.MAX_ARGS:
            msg = f"Command exceeds maximum argument limit of {self.MAX_ARGS}."
            return ActionResult(ActionStatus.FAIL_PRECONDITION, msg)

        # Command must be specified by its name, not a path, to prevent path injection.
        exe = Path(self.cmd[0]).name
        if self.cmd[0] != exe:
            msg = f"Executable '{self.cmd[0]}' must not contain a path. Use whitelist."
            return ActionResult(ActionStatus.FAIL_UNAUTHORIZED, msg)

        if exe not in self.allowed_whitelist:
            msg = f"Executable '{exe}' is not in the allowed whitelist."
            return ActionResult(ActionStatus.FAIL_UNAUTHORIZED, msg)

        return None

    def run(self) -> ActionResult:
        if precondition_failure := self._validate_preconditions():
            _logger.warning("Command precondition failed: %s", precondition_failure.message)
            return precondition_failure

        try:
            _logger.debug("Executing whitelisted command: %r", self.cmd)
            result = self.shell.run(
                self.cmd,
                capture_output=self.capture_output,
                check=True,  # Raises CalledProcessError on non-zero exit codes
                timeout=self.timeout,
            )
            _logger.info("Command succeeded: %r", self.cmd)
            return ActionResult(status=ActionStatus.OK, output=result.stdout)

        except subprocess.TimeoutExpired:
            msg = f"Command timed out after {self.timeout}s."
            _logger.error("%s Command: %r", msg, self.cmd)
            return ActionResult(status=ActionStatus.FAIL_TIMEOUT, message=msg)

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else b""
            msg = f"Command failed with exit code {e.returncode}."
            _logger.error("%s Command: %r, Stderr: %r", msg, self.cmd, stderr)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg, output=stderr)

        except (FileNotFoundError, PermissionError) as e:
            msg = f"Command executable could not be run: {e}"
            _logger.error("%s Command: %r", msg, self.cmd)
            return ActionResult(status=ActionStatus.FAIL_EXECUTION, message=msg)
