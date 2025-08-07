import logging
from typing import List, Optional, Tuple
from ._actions import Action, ActionResult, ActionStatus


_logger = logging.getLogger(__name__)


class GenericBuilderError(Exception):
    """
    Custom exception raised when an action fails during the build process.

    This exception contains the full result of the action that failed,
    allowing for precise, context-rich error handling and reporting without
    exposing the action's internal state.
    """

    def __init__(self, failed_result: ActionResult):
        self.failed_result = failed_result
        # Create a clear, safe error message from the result of the failed action.
        super().__init__(
            f"Action failed with status '{failed_result.status.name}': {failed_result.message}"
        )


class Builder:
    """
    Executes a sequence of Actions in a secure, fail-fast manner.

    The Builder is designed to be reliable and secure. It operates on an
    immutable sequence of actions and stops at the first sign of failure to
    prevent the system from entering an unknown or insecure state.
    """

    def __init__(self, actions: List[Action], logger: Optional[logging.Logger] = None):
        """
        Initializes the Builder.

        Security Note: Stores an immutable copy of the actions (as a tuple)
        to prevent post-initialization tampering of the action sequence (TOCTOU).
        This guarantees the integrity of the build plan.
        """
        self._actions: Tuple[Action, ...] = tuple(actions)
        self.logger = logger or _logger

    def build(self) -> None:
        """
        Runs all actions in sequence.

        The builder will execute each action in the order provided. If any action
        does not return `ActionStatus.OK`, execution is halted immediately.

        Raises:
            GenericBuilderError: On the first action that fails. The exception
                                 contains the complete `ActionResult` for robust
                                 upstream error handling. The system state is left
                                 as-is at the point of failure.
        """
        self.logger.info("Builder starting execution with %d actions.", len(self._actions))

        for i, action in enumerate(self._actions, 1):
            # Use the class name for logging to avoid accidentally logging
            # sensitive data from the action's __str__ or __repr__ method.
            action_name = action.__class__.__name__
            self.logger.debug("Running action %d/%d: %s", i, len(self._actions), action_name)

            result = action.run()

            # The contract is that every action returns a rich ActionResult object.
            # We check the status attribute of this object.
            if result.status == ActionStatus.OK:
                # Log the specific, safe success message from the action's result.
                # This provides a clear and secure audit trail of what was done.
                self.logger.info("Action '%s' succeeded: %s", action_name, result.message)
                continue

            # --- Failure Path ---
            # On failure, log the safe message from the result and raise a
            # detailed, exception.
            self.logger.error(
                "Halting build. Action '%s' failed with status '%s'. Reason: %s",
                action_name,
                result.status.name,
                result.message,
            )

            raise GenericBuilderError(result)

        self.logger.info("Build completed successfully.")
