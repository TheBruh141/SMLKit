import logging
import pytest
from unittest.mock import MagicMock, call, ANY

# Correct the import paths to match the project's file structure.
from src.utils.builder._builder import Builder, GenericBuilderError
from src.utils.builder._actions import Action, ActionResult, ActionStatus


@pytest.fixture
def mock_logger(mocker):
    """Provides a mock logger to inspect log calls."""
    # Use the correct, full path to the logger variable inside the _builder.py module.
    return mocker.patch("src.utils.builder._builder._logger", autospec=True)


# --- Reusable Mock Action Factory ---


def make_mock_action(mocker, name: str, return_value: ActionResult) -> Action:
    """
    Helper factory to create a mock Action with a specific, unique class name.
    """
    # FIX: Create a separate mock for the class to give it a unique name,
    # preventing side effects between different action instances.
    mock_class = MagicMock()
    mock_class.__name__ = name

    # Create the mock instance of the Action
    action_instance = mocker.create_autospec(Action, instance=True)

    # Assign our custom mock class to the instance's __class__ attribute.
    action_instance.__class__ = mock_class
    action_instance.run.return_value = return_value
    return action_instance


# ==============================================================================
#  Test Suite for Builder
# ==============================================================================


class TestBuilderHappyPath:
    """Tests the ideal execution path where all actions succeed."""

    def test_build_succeeds_with_multiple_actions(self, mock_logger, mocker):
        """BRANCH: Verifies sequential execution on a full success path."""
        # Arrange
        action1_result = ActionResult(ActionStatus.OK, "Step 1 complete.")
        action2_result = ActionResult(ActionStatus.OK, "Step 2 complete.")

        action1 = make_mock_action(mocker, "ActionOne", action1_result)
        action2 = make_mock_action(mocker, "ActionTwo", action2_result)

        builder = Builder(actions=[action1, action2])

        # Act
        builder.build()

        # Assert
        action1.run.assert_called_once()
        action2.run.assert_called_once()
        expected_logs = [
            call.info("Builder starting execution with %d actions.", 2),
            call.debug("Running action %d/%d: %s", 1, 2, "ActionOne"),
            call.info("Action '%s' succeeded: %s", "ActionOne", "Step 1 complete."),
            call.debug("Running action %d/%d: %s", 2, 2, "ActionTwo"),
            call.info("Action '%s' succeeded: %s", "ActionTwo", "Step 2 complete."),
            call.info("Build completed successfully."),
        ]
        mock_logger.assert_has_calls(expected_logs)


class TestBuilderFailureScenarios:
    """Tests the builder's fail-fast behavior."""

    @pytest.mark.parametrize(
        "failure_index", [0, 1, 2], ids=["fail_first", "fail_middle", "fail_last"]
    )
    def test_build_halts_on_first_failure(self, failure_index, mock_logger, mocker):
        """
        BRANCH: Verifies that the build stops immediately upon any action failure
        and does not execute subsequent actions.
        """
        # Arrange
        actions = [
            make_mock_action(mocker, "ActionSuccess1", ActionResult(ActionStatus.OK, "OK")),
            make_mock_action(mocker, "ActionSuccess2", ActionResult(ActionStatus.OK, "OK")),
            make_mock_action(mocker, "ActionSuccess3", ActionResult(ActionStatus.OK, "OK")),
        ]
        failure_result = ActionResult(
            ActionStatus.FAIL_EXECUTION, "Disk is full", output=b"Error code: 5"
        )
        failing_action = make_mock_action(mocker, "ActionFail", failure_result)
        actions.insert(failure_index, failing_action)
        builder = Builder(actions=actions)

        # Act & Assert
        with pytest.raises(GenericBuilderError) as excinfo:
            builder.build()

        assert excinfo.value.failed_result is failure_result
        for i in range(failure_index + 1):
            actions[i].run.assert_called_once()
        for i in range(failure_index + 1, len(actions)):
            actions[i].run.assert_not_called()
        mock_logger.error.assert_called_once_with(
            "Halting build. Action '%s' failed with status '%s'. Reason: %s",
            "ActionFail",
            "FAIL_EXECUTION",
            "Disk is full",
        )


class TestBuilderSecurityAndEdgeCases:
    """Tests for security vulnerabilities and unusual inputs."""

    def test_build_with_empty_action_list_succeeds_gracefully(self, mock_logger):
        """EDGE CASE: Builder should not fail when given no actions to run."""
        builder = Builder(actions=[])
        builder.build()
        expected_logs = [
            call.info("Builder starting execution with %d actions.", 0),
            call.info("Build completed successfully."),
        ]
        mock_logger.assert_has_calls(expected_logs)

    def test_builder_is_immutable_to_post_init_mutation(self, mocker):
        """
        SECURITY (TOCTOU): Verifies the builder is immune to its original
        action list being modified after initialization.
        """
        action_list = [make_mock_action(mocker, "LegitAction", ActionResult(ActionStatus.OK, "OK"))]
        builder = Builder(actions=action_list)
        malicious_action = make_mock_action(
            mocker, "MaliciousAction", ActionResult(ActionStatus.OK, "pwned")
        )
        action_list.append(malicious_action)

        builder.build()

        action_list[0].run.assert_called_once()
        malicious_action.run.assert_not_called()

    def test_builder_does_not_log_sensitive_action_data(self, mock_logger):
        """
        SECURITY (Information Disclosure): Verifies the builder only logs the
        action's class name and safe result message, not its internal state.
        """

        class SensitiveAction(Action):
            def __init__(self, secret: str):
                self.secret = secret

            def run(self) -> ActionResult:
                return ActionResult(ActionStatus.OK, "Sensitive action completed.")

            def __str__(self):
                return f"SensitiveAction(secret='{self.secret}')"

        secret_data = "aws_secret_key_12345"
        builder = Builder(actions=[SensitiveAction(secret=secret_data)])
        builder.build()
        all_log_output = " ".join(map(str, mock_logger.mock_calls))
        assert secret_data not in all_log_output
        assert "SensitiveAction" in all_log_output
