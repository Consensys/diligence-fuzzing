import os
import shutil
from pathlib import Path
from typing import Optional

import pytest
import yaml
from click.testing import CliRunner

from fuzzing_cli.cli import cli

UP = "\x1b\x5b\x41"
DOWN = "\x1b\x5b\x42"
LEFT = "\x1b\x5b\x44"
RIGHT = "\x1b\x5b\x43"


def test_generate_config(tmp_path, isolated_hardhat_project):
    os.chdir(tmp_path)
    actions = ["y", "y", "n", "y", "http://localhost:1111/", "4", "\n"]
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-config"], input="\n".join(actions))
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        config = yaml.load(f)
    assert config == {
        "analyze": None,
        "fuzz": {
            "build_directory": str(Path(tmp_path).joinpath("artifacts")),
            "targets": [str(Path(tmp_path).joinpath("contracts"))],
            "rpc_url": "http://localhost:1111/",
            "number_of_cores": 4,
            "campaign_name_prefix": Path(tmp_path).name.lower().replace("-", "_"),
        },
    }
