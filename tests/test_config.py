import pytest
import logging
from pathlib import Path
import shutil
import sys

from src.utils import Config, parse_args


def test_for_structure_sets_dot_as_dest(tmp_path):
    # When constructing for structure
    config = Config.for_structure()

    # Then dest should be current directory
    assert config.dest_project_location == Path('.').resolve()
    assert config.action == 'project_structure'


def test_for_serve_edit_validate_containerize(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    for method_name, action in [
        ('for_serve', 'serve'),
        ('for_edit', 'edit'),
        ('for_validate', 'validate'),
        ('for_containerize', 'containerize')
    ]:
        root = tmp_path / action
        # create dummy dir
        root.mkdir()
        method = getattr(Config, method_name)
        config = method(root)
        assert config.dest_project_location == root
        assert config.action == action
        # Check printed output via caplog for serve/edit uses print in classmethod
        # but we can at least verify config creation


def test_execute_actions_print_and_log(caplog, tmp_path, capsys):
    caplog.set_level(logging.INFO)
    # init
    init_dir = tmp_path / "init_proj"
    config_init = Config.for_init(init_dir)
    config_init.execute()
    captured = capsys.readouterr()
    assert "Initializing new project at:" in captured.out
    assert any("Project initialized successfully" in rec.message for rec in caplog.records)

    # project_structure
    config_struct = Config.for_structure()
    config_struct.execute()
    captured = capsys.readouterr()
    assert "Project structure:" in captured.out


def test_parse_args_init(tmp_path, monkeypatch):
    # Simulate CLI args for init
    test_path = tmp_path / "cli_proj"
    monkeypatch.setattr(sys, 'argv', ['smlkit_cli.py', '--init', str(test_path)])
    config = parse_args()
    assert isinstance(config, Config)
    assert config.action == 'init'
    assert config.dest_project_location == test_path


def test_parse_args_missing_action(monkeypatch):
    # No args should raise SystemExit
    monkeypatch.setattr(sys, 'argv', ['smlkit_cli.py'])
    with pytest.raises(SystemExit):
        parse_args()
