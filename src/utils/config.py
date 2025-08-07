import argparse
from dataclasses import dataclass, field
from pathlib import Path
import logging
import sys
from typing import Union, TextIO, Optional


@dataclass
class Config:
    """
    Configuration and action executor for smlkit CLI.

    Uses factory methods (constructor pattern) to build a Config ready to run an action.
    """

    smlkit_root_location: Path = field(init=False)
    dest_project_location: Path = field(init=False)
    action: str = field(init=False)

    logging_level: int = logging.INFO
    logging_out_stream: Union[TextIO, None] = sys.stderr

    def __init__(self, dest_project_location: Path, action: str):
        # Initialize paths
        if action == 'project_structure':
            # No actual dest folder needed
            dest_project_location = Path('.')
        elif not dest_project_location:
            raise ValueError("Destination project location is required for this action.")

        # Create destination folder for init
        if action == 'init' and not dest_project_location.exists():
            dest_project_location.mkdir(parents=True, exist_ok=True)

        self.smlkit_root_location = Path(__file__).resolve().parent
        self.dest_project_location = dest_project_location.resolve()
        self.action = action

        # Configure logging once
        root_logger = logging.getLogger()
        if not root_logger.hasHandlers():
            logging.basicConfig(
                level=self.logging_level,
                stream=self.logging_out_stream,
                format="%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        else:
            root_logger.setLevel(self.logging_level)
        logging.debug(f"Initialized Config: action={action}, dest={dest_project_location}")
        logging.debug(f"smlkit root location: {self.smlkit_root_location}")

    @classmethod
    def for_init(cls, path: Path) -> 'Config':
        print(f"Initializing new project at: {path}")
        return cls(dest_project_location=path, action='init')

    @classmethod
    def for_structure(cls) -> 'Config':
        return cls(dest_project_location=Path('.'), action='project_structure')

    @classmethod
    def for_serve(cls, root: Path) -> 'Config':
        print(f"Serving project dashboard for: {root}")
        return cls(dest_project_location=root, action='serve')

    @classmethod
    def for_edit(cls, root: Path) -> 'Config':
        print(f"Editing project at: {root}")
        return cls(dest_project_location=root, action='edit')

    @classmethod
    def for_validate(cls, root: Path) -> 'Config':
        print(f"Validating project at: {root}")
        return cls(dest_project_location=root, action='validate')

    @classmethod
    def for_containerize(cls, root: Path) -> 'Config':
        print(f"Containerizing project at: {root}")
        return cls(dest_project_location=root, action='containerize')

    def execute(self) -> None:
        """Run the selected action."""
        match self.action:
            case 'init':
                logging.info("Project initialized successfully at %s", self.dest_project_location)
                # further scaffolding logic here

            case 'project_structure':
                structure = [
                    "<project_root>/",  # noqa: W605
                    "├── data/",
                    "├── notebooks/",
                    "├── src/",
                    "├── models/",
                    "└── config.yaml",
                ]
                print("Project structure:")
                print("\n".join(structure))

            case 'serve':
                # Placeholder for serve logic
                logging.info("Launching dashboard for %s", self.dest_project_location)

            case 'edit':
                # Placeholder for edit logic
                logging.info("Entering interactive editor for %s", self.dest_project_location)

            case 'validate':
                # Placeholder for validation logic
                logging.info("Validation completed for %s", self.dest_project_location)

            case 'containerize':
                # Placeholder for containerization logic
                logging.info("Container built for %s", self.dest_project_location)

            case _:
                logging.error("Unknown action: %s", self.action)


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="smlkit: A command-line tool for managing machine learning projects."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--init",
        dest="init_path",
        metavar="PATH",
        type=Path,
        help="Initialize a new smlkit project at the specified path.",
    )
    group.add_argument(
        "--project-structure", action="store_true", help="Display the predefined project structure."
    )
    group.add_argument(
        "--serve",
        "-s",
        dest="serve_root",
        metavar="PROJECT_ROOT",
        type=Path,
        help="Launch the web-based dashboard for an existing project.",
    )
    group.add_argument(
        "--edit",
        dest="edit_root",
        metavar="PROJECT_ROOT",
        type=Path,
        help="Interactively edit components of your project.",
    )
    group.add_argument(
        "--validate",
        dest="validate_root",
        metavar="PROJECT_ROOT",
        type=Path,
        help="Validate your project for naming conventions and structure.",
    )
    group.add_argument(
        "--containerize",
        dest="containerize_root",
        metavar="PROJECT_ROOT",
        type=Path,
        help="Package your project into a Docker container.",
    )

    args = parser.parse_args()

    if args.init_path:
        return Config.for_init(args.init_path)
    if args.project_structure:
        return Config.for_structure()
    if args.serve_root:
        return Config.for_serve(args.serve_root)
    if args.edit_root:
        return Config.for_edit(args.edit_root)
    if args.validate_root:
        return Config.for_validate(args.validate_root)
    if args.containerize_root:
        return Config.for_containerize(args.containerize_root)

    parser.error("No valid action provided.")
