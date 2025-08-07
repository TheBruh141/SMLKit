import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Protocol, Union
import subprocess
import tempfile
import logging

# Set up a dedicated logger for this module.
log = logging.getLogger(__name__)


class Shell(Protocol):
    """
    Abstract interface for executing shell commands.

    Security Note: Implementations must prioritize preventing command injection
    vulnerabilities. Avoid using 'shell=True' with untrusted input.
    Always favor passing commands as a list of arguments.
    """

    @abstractmethod
    def run(
        self,
        cmd: List[str],
        cwd: Optional[Path] = None,
        capture_output: bool = True,
        check: bool = True,
        timeout: Optional[float] = None,
    ) -> subprocess.CompletedProcess[str]: ...


class FileSystem(Protocol):
    """
    Abstract interface for filesystem operations.

    Security Note: Implementations must be designed to mitigate race conditions
    (TOCTOU - Time-of-Check to Time-of-Use), protect against symbolic link
    attacks, and ensure atomic operations where necessary to prevent data
    corruption or partial writes.
    """

    @abstractmethod
    def mkdir(self, path: Path, parents: bool = False, exist_ok: bool = False) -> None: ...

    @abstractmethod
    def write_file_atomic(
        self, path: Path, content: Union[str, bytes], encoding: str = "utf-8"
    ) -> None: ...

    @abstractmethod
    def is_file(self, path: Path) -> bool: ...

    @abstractmethod
    def is_dir(self, path: Path) -> bool: ...

    @abstractmethod
    def list_dir(self, path: Path) -> List[Path]: ...

    @abstractmethod
    def remove_file(self, path: Path) -> None: ...

    @abstractmethod
    def remove_dir(self, path: Path) -> None: ...

    @abstractmethod
    def is_symlink(self, path: Path) -> bool:
        """Checks if a path is a symbolic link."""
        ...

    @abstractmethod
    def open(self, path: str, flags: int) -> int:
        """Opens a file and returns a file descriptor, respecting flags."""
        ...

    @abstractmethod
    def close(self, fd: int) -> None:
        """Closes a file descriptor."""
        ...


class DefaultShell:
    """
    Default implementation of Shell using subprocess.
    """

    def run(
        self,
        cmd: List[str],
        cwd: Optional[Path] = None,
        capture_output: bool = True,
        check: bool = True,
        timeout: Optional[float] = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Executes a command in a subprocess.

        Security Best Practices:
        - shell=False is explicitly enforced by passing 'cmd' as a list.
        This is a critical security measure to prevent shell injection. [3, 4]
        - Input should be sanitized before being passed to this method.
        While this implementation is safer, it's not a replacement for
        input validation.
        """
        # The 'shell' argument is intentionally omitted and defaults to False,
        # which is the secure setting.
        return subprocess.run(
            cmd, cwd=cwd, capture_output=capture_output, text=True, check=check, timeout=timeout
        )


class DefaultFileSystem:
    """
    Default implementation of FileSystem using pathlib and builtins.
    Hardened for security.
    """

    def mkdir(self, path: Path, parents: bool = False, exist_ok: bool = False) -> None:
        """
        Creates a directory.

        Security Note: This operation is generally safe, but be aware of the
        permissions set on the created directory, especially in a multi-user
        environment. The default permissions are inherited from the umask.
        """
        path.mkdir(parents=parents, exist_ok=exist_ok)

    def write_file_atomic(
        self, path: Path, content: Union[str, bytes], encoding: str = "utf-8"
    ) -> None:
        """
        Atomically writes content to a file. [1, 2]

        This is achieved by writing to a temporary file in the same directory and
        then atomically moving it to the final destination. This prevents partial
        writes in case of an interruption. [5]

        Security Note: Using a temporary file in the same directory ensures the
        move operation is atomic across different filesystems. [1]
        """
        mode = 'w' if isinstance(content, str) else 'wb'
        # The tempfile module is used to create a secure temporary file,
        # avoiding predictable file names. [7, 8]
        try:
            with tempfile.NamedTemporaryFile(
                mode=mode,
                dir=path.parent,
                delete=False,
                encoding=encoding if 'b' not in mode else None,
            ) as tmp_file:
                tmp_file.write(content)
                # Ensure data is written to the temporary file before the move.
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                temp_path = Path(tmp_file.name)
            # os.replace provides an atomic move/rename operation.
            os.replace(temp_path, path)
        except Exception as e:
            log.error(f"Failed to atomically write to {path}: {e}")
            # Clean up the temporary file in case of an error.
            if 'temp_path' in locals() and temp_path.exists():
                temp_path.unlink()
            raise

    def is_file(self, path: Path) -> bool:
        """
        Checks if a path is a file, following symlinks.

        Security Note: Be aware that the state of the path could change between
        this check and a subsequent operation (TOCTOU vulnerability). [6, 26]
        """
        return path.is_file()

    def is_dir(self, path: Path) -> bool:
        """
        Checks if a path is a directory, following symlinks.

        Security Note: Similar to is_file, this is susceptible to TOCTOU
        vulnerabilities.
        """
        return path.is_dir()

    def list_dir(self, path: Path) -> List[Path]:
        return list(path.iterdir())

    def remove_file(self, path: Path) -> None:
        """
        Removes a file.

        Security Note: Checks for symlinks to avoid unintended deletions.
        """
        if self.is_symlink(path):
            log.warning(f"Attempted to remove a symbolic link: {path}. Operation aborted.")
            return
        if path.is_file():
            path.unlink()

    def remove_dir(self, path: Path) -> None:
        """
        Recursively removes a directory and its contents.

        Security Note: This is a destructive operation. Ensure the path is
        what you expect before calling. Checks for symbolic links to the top-level
        directory are included.
        """
        if self.is_symlink(path):
            log.warning(
                f"Attempted to remove a symbolic link to a directory: {path}. Operation aborted."
            )
            return
        if path.is_dir():
            shutil.rmtree(path)

    def is_symlink(self, path: Path) -> bool:
        """Checks if a path is a symbolic link."""
        return path.is_symlink()

    def open(self, path: str, flags: int) -> int:
        """Opens a file and returns a file descriptor, respecting flags."""
        return os.open(path, flags)

    def close(self, fd: int) -> None:
        """Closes a file descriptor."""
        os.close(fd)
