import os
import subprocess
from pathlib import Path
from typing import List, Sequence, Union

import pytest
from pytest_mock import MockerFixture

# Assume the code to be tested is in a file named `actions.py`
from src.utils.builder import (
    ActionStatus,
    CheckDirectoryAction,
    CheckFileAction,
    CommandAction,
    CreateDirectoryAction,
    CreateFileAction,
    FileSystem,
)

# ── Mock Interfaces for Dependency Injection ─────────────────────────────────


class Shell:
    """A mockable spec for the Shell interface."""

    def run(
        self, cmd: Sequence[str], capture_output: bool, check: bool, timeout: float
    ) -> subprocess.CompletedProcess: ...


# ── Test Suite ───────────────────────────────────────────────────────────────


@pytest.fixture
def mock_fs(mocker: MockerFixture) -> FileSystem:
    """Provides a MagicMock object that conforms to the FileSystem protocol spec."""
    return mocker.MagicMock(spec=FileSystem)


@pytest.fixture
def mock_shell(mocker: MockerFixture) -> Shell:
    """Provides a mock Shell object."""
    return mocker.MagicMock(spec=Shell)


@pytest.fixture
def allowed_base(tmp_path: Path) -> Path:
    """Provides a safe, temporary base directory."""
    return tmp_path / "safe_zone"


# ==============================================================================
#  Tests for SecurePathMixin (via other actions)
# ==============================================================================


class TestSecurePathMixin:
    def test_path_escape_triggers_unauthorized(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Verifies the `is_relative_to` check fails."""
        malicious_path = allowed_base.parent / "unsafe_file"

        action = CreateDirectoryAction(path=malicious_path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "Path escape attempt" in result.message

    def test_symlink_in_parent_triggers_unauthorized(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Verifies the symlink check in the parent path fails."""
        path_with_symlink_parent = allowed_base / "symlinked_dir" / "target"

        # Correctly mock the symlink check to fire on the malicious component
        mock_fs.is_symlink.side_effect = lambda p: p == (allowed_base / "symlinked_dir")

        action = CreateDirectoryAction(
            path=path_with_symlink_parent, fs=mock_fs, allowed_base=allowed_base
        )
        result = action.run()

        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "Symlink detected in path component" in result.message


# ==============================================================================
#  Tests for CreateDirectoryAction
# ==============================================================================


class TestCreateDirectoryAction:
    def test_create_dir_success(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Happy path."""
        path = allowed_base / "new_dir"
        mock_fs.is_symlink.return_value = False

        action = CreateDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.OK
        mock_fs.mkdir.assert_called_once_with(path, parents=True, exist_ok=False)

    def test_create_dir_fails_if_path_is_symlink(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Verifies failure if the final path component is a symlink."""
        path = allowed_base / "new_dir"
        mock_fs.is_symlink.side_effect = lambda p: p == path

        action = CreateDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "Path cannot be a symlink" in result.message

    def test_create_dir_fails_on_permission_error(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Covers the `except (ValueError, PermissionError)` block."""
        path = allowed_base / "new_dir"
        mock_fs.is_symlink.return_value = False
        mock_fs.mkdir.side_effect = PermissionError("Access denied")

        action = CreateDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "Access denied" in result.message

    def test_create_dir_fails_on_io_error(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Covers the `except (IOError, OSError)` block."""
        path = allowed_base / "new_dir"
        mock_fs.is_symlink.return_value = False
        mock_fs.mkdir.side_effect = IOError("Disk full")

        action = CreateDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "Disk full" in result.message


# ==============================================================================
#  Tests for CreateFileAction
# ==============================================================================


class TestCreateFileAction:
    def test_create_file_success_parent_exists(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Happy path where parent directory already exists."""
        path = allowed_base / "new_file.txt"
        mock_fs.is_symlink.return_value = False
        mock_fs.is_dir.return_value = True

        action = CreateFileAction(path=path, content="hello", fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.OK
        mock_fs.mkdir.assert_not_called()
        mock_fs.write_file_atomic.assert_called_once_with(path, "hello")

    def test_create_file_success_parent_created(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Path where parent directory does NOT exist and is created."""
        path = allowed_base / "subdir" / "new_file.txt"
        mock_fs.is_symlink.return_value = False
        mock_fs.is_dir.return_value = False

        action = CreateFileAction(path=path, content="hello", fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.OK
        mock_fs.mkdir.assert_called_once_with(path.parent, parents=True, exist_ok=True)
        mock_fs.write_file_atomic.assert_called_once_with(path, "hello")

    def test_create_file_fails_on_permission_error(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Covers the `PermissionError` during write."""
        path = allowed_base / "new_file.txt"
        mock_fs.is_symlink.return_value = False
        mock_fs.is_dir.return_value = True
        mock_fs.write_file_atomic.side_effect = PermissionError("Read-only filesystem")

        action = CreateFileAction(path=path, content="hello", fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "Read-only filesystem" in result.message

    def test_create_file_fails_on_os_error(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Covers the `(IOError, OSError)` during write."""
        path = allowed_base / "new_file.txt"
        mock_fs.is_symlink.return_value = False
        mock_fs.is_dir.return_value = True
        mock_fs.write_file_atomic.side_effect = OSError("Something went wrong")

        action = CreateFileAction(path=path, content="hello", fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "Something went wrong" in result.message


# ==============================================================================
#  Tests for CheckFileAction
# ==============================================================================


class TestCheckFileAction:
    def test_check_file_success(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Happy path."""
        path = allowed_base / "file.txt"
        # FIX: Explicitly mock the security pre-check to pass.
        mock_fs.is_symlink.return_value = False
        mock_fs.open.return_value = 123

        action = CheckFileAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.OK
        mock_fs.open.assert_called_once_with(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        mock_fs.close.assert_called_once_with(123)

    @pytest.mark.parametrize("error", [IsADirectoryError, FileNotFoundError, OSError])
    def test_check_file_fails_on_execution_errors(
        self, error, mock_fs: FileSystem, allowed_base: Path
    ):
        """BRANCH: Covers all `except (IsADirectoryError, ...)` paths."""
        path = allowed_base / "file.txt"
        # FIX: Explicitly mock the security pre-check to pass.
        mock_fs.is_symlink.return_value = False
        mock_fs.open.side_effect = error("Mocked OS Error")

        action = CheckFileAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "Mocked OS Error" in result.message


# ==============================================================================
#  Tests for CheckDirectoryAction
# ==============================================================================


class TestCheckDirectoryAction:
    def test_check_dir_success(self, mock_fs: FileSystem, allowed_base: Path):
        """BRANCH: Happy path."""
        path = allowed_base / "dir"
        # FIX: Explicitly mock the security pre-check to pass.
        mock_fs.is_symlink.return_value = False
        mock_fs.open.return_value = 123

        action = CheckDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.OK
        mock_fs.open.assert_called_once_with(
            str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        mock_fs.close.assert_called_once_with(123)

    @pytest.mark.parametrize("error", [NotADirectoryError, FileNotFoundError, OSError])
    def test_check_dir_fails_on_execution_errors(
        self, error, mock_fs: FileSystem, allowed_base: Path
    ):
        """BRANCH: Covers all `except (NotADirectoryError, ...)` paths."""
        path = allowed_base / "dir"
        # FIX: Explicitly mock the security pre-check to pass.
        mock_fs.is_symlink.return_value = False
        mock_fs.open.side_effect = error("Mocked OS Error")

        action = CheckDirectoryAction(path=path, fs=mock_fs, allowed_base=allowed_base)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "Mocked OS Error" in result.message


# ==============================================================================
#  Tests for CommandAction
# ==============================================================================


class TestCommandAction:
    whitelist = ["ls", "echo", "sleep", "nonexistent_command"]

    def test_command_success(self, mock_shell: Shell):
        """BRANCH: Happy path."""
        cmd = ["ls", "-la"]
        mock_shell.run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=b"files"
        )

        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()

        assert result.status == ActionStatus.OK
        assert result.output == b"files"

    def test_command_fails_on_empty_cmd(self, mock_shell: Shell):
        """BRANCH: Precondition `if not self.cmd`."""
        action = CommandAction(cmd=[], shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()
        assert result.status == ActionStatus.FAIL_PRECONDITION
        assert "Command cannot be empty" in result.message

    def test_command_fails_on_too_many_args(self, mock_shell: Shell):
        """BRANCH: Precondition `if len(self.cmd) > self.MAX_ARGS`."""
        long_cmd = ["echo"] + ["a"] * CommandAction.MAX_ARGS
        action = CommandAction(cmd=long_cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()
        assert result.status == ActionStatus.FAIL_PRECONDITION
        assert "exceeds maximum argument limit" in result.message

    def test_command_fails_if_exe_contains_path(self, mock_shell: Shell):
        """BRANCH: Precondition `if self.cmd[0] != exe`."""
        cmd = ["/bin/ls", "-la"]
        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()
        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "must not contain a path" in result.message

    def test_command_fails_if_not_in_whitelist(self, mock_shell: Shell):
        """BRANCH: Precondition `if exe not in self.allowed_whitelist`."""
        cmd = ["rm", "-rf", "/"]
        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()
        assert result.status == ActionStatus.FAIL_UNAUTHORIZED
        assert "not in the allowed whitelist" in result.message

    def test_command_fails_on_timeout(self, mock_shell: Shell):
        """BRANCH: `except subprocess.TimeoutExpired`."""
        cmd = ["sleep", "100"]
        mock_shell.run.side_effect = subprocess.TimeoutExpired(cmd, timeout=30.0)

        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()

        assert result.status == ActionStatus.FAIL_TIMEOUT
        assert "timed out" in result.message

    def test_command_fails_on_called_process_error(self, mock_shell: Shell):
        """BRANCH: `except subprocess.CalledProcessError`."""
        cmd = ["ls", "/nonexistent"]
        mock_shell.run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=cmd,
            stderr=b"ls: cannot access '/nonexistent': No such file or directory",
        )

        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "failed with exit code 1" in result.message
        assert result.output == b"ls: cannot access '/nonexistent': No such file or directory"

    def test_command_fails_on_file_not_found(self, mock_shell: Shell):
        """BRANCH: `except (FileNotFoundError, PermissionError)` with FileNotFoundError."""
        cmd = ["nonexistent_command"]
        mock_shell.run.side_effect = FileNotFoundError("command not found")

        action = CommandAction(cmd=cmd, shell=mock_shell, allowed_whitelist=self.whitelist)
        result = action.run()

        assert result.status == ActionStatus.FAIL_EXECUTION
        assert "command not found" in result.message
