import os
import shutil
from pathlib import Path
from typing import Optional

import pytest
import yaml
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture

from fuzzing_cli.cli import cli

UP = "\x1b\x5b\x41"
DOWN = "\x1b\x5b\x42"
LEFT = "\x1b\x5b\x44"
RIGHT = "\x1b\x5b\x43"


@pytest.mark.parametrize(
    "ide, target, build_dir",
    [
        (lazy_fixture("isolated_truffle_project"), "contracts", "build/contracts"),
        (lazy_fixture("isolated_hardhat_project"), "contracts", "artifacts"),
        (lazy_fixture("isolated_brownie_project"), "contracts", "build/contracts"),
    ],
)
@pytest.mark.parametrize(
    "rm_target, custom_target, rm_build_dir, custom_build_dir",
    [
        (False, None, False, None),
        (False, "contracts/sample.sol", False, None),
        (
            False,
            "contracts/sample.sol, contracts/test1.sol,test_dir/test2.sol",
            False,
            None,
        ),
        (True, "contracts/sample.sol", False, None),
        (
            True,
            "contracts/sample.sol, contracts/test1.sol,test_dir/test2.sol",
            False,
            None,
        ),
        (False, None, False, "test_build_dir"),
        (False, None, True, "test_build_dir"),
    ],
)
def test_generate_config(
    tmp_path,
    ide,
    target: str,
    build_dir: str,
    rm_target: bool,
    custom_target: Optional[str],
    rm_build_dir: bool,
    custom_build_dir: Optional[str],
):
    os.chdir(tmp_path)

    target_commands = ["y"]
    if custom_target:
        if rm_target:
            shutil.rmtree(f"{tmp_path}/{target}")
            target_commands = [custom_target]
        else:
            target_commands = ["N", custom_target]

        custom_target = [
            str(Path.cwd().absolute().joinpath(t.strip()))
            for t in custom_target.split(",")
        ]

    build_dir_commands = ["y"]
    if custom_build_dir:
        if rm_build_dir:
            shutil.rmtree(f"{tmp_path}/{build_dir}")
            build_dir_commands = [custom_build_dir]
        else:
            build_dir_commands = ["N", custom_build_dir]

        custom_build_dir = str(Path.cwd().absolute().joinpath(custom_build_dir))

    keystrokes = ["y"] + target_commands + build_dir_commands + ["", "3", "", "", ""]
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-config"], input="\n".join(keystrokes))
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        config = yaml.load(f)
    assert config == {
        "ci": True,
        "confirm": True,
        "fuzz": {
            "build_directory": custom_build_dir
            or str(Path(tmp_path).joinpath(build_dir)),
            "targets": custom_target or [str(Path(tmp_path).joinpath(target))],
            "rpc_url": "http://localhost:7545",
            "number_of_cores": 3,
            "campaign_name_prefix": Path(tmp_path).name.lower().replace("-", "_"),
            "api_key": None,
            "faas_url": "https://fuzzing.diligence.tools",
        },
    }


def test_no_ide(tmp_path):
    os.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-config"], input="y\n")
    assert result.exit_code == 2
    assert (
        "Error: Projects using plain solidity files is not supported right now"
        in result.output
    )


@pytest.mark.parametrize(
    "rpc_url, num_cores, name_prefix, api_key",
    [
        ("http://localhost:7777/", None, None, None),
        (None, "4", None, None),
        (None, None, "test-campaign-1", None),
        (None, None, None, "test-api-key-1"),
        ("http://localhost:10000", "2", "test-campaign-2", "test-api-key-2"),
    ],
)
def test_campaign_parameters_provision(
    tmp_path,
    isolated_truffle_project,
    rpc_url: Optional[str],
    num_cores: Optional[str],
    name_prefix: Optional[str],
    api_key: Optional[str],
):
    os.chdir(tmp_path)

    keystrokes = [
        "y",
        "y",
        "y",
        rpc_url or "",
        num_cores or "",
        name_prefix or "",
        api_key or "",
        "",
    ]

    runner = CliRunner()
    result = runner.invoke(cli, ["generate-config"], input="\n".join(keystrokes))
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        config = yaml.load(f)
    assert config == {
        "ci": True,
        "confirm": True,
        "fuzz": {
            "build_directory": str(Path(tmp_path).joinpath("build/contracts")),
            "targets": [str(Path(tmp_path).joinpath("contracts"))],
            "rpc_url": rpc_url or "http://localhost:7545",
            "number_of_cores": int(num_cores or 1),
            "campaign_name_prefix": name_prefix
            or Path(tmp_path).name.lower().replace("-", "_"),
            "api_key": api_key or None,
            "faas_url": "https://fuzzing.diligence.tools",
        },
    }


def test_sync_without_config(tmp_path, isolated_truffle_project):
    os.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["generate-config", "--sync"], input="contracts/sample.sol\n"
    )
    assert result.exit_code == 2
    assert "Could not find config file to re-sync. Create one first." in result.output


@pytest.mark.parametrize(
    "custom_target, rm_target",
    [
        (None, False),
        ("contracts/sample.sol", False),
        ("contracts/sample1.sol, contracts/sample2.sol,contracts/sample3.sol", False),
        ("contracts/sample1.sol", True),
    ],
)
def test_syncing(
    tmp_path, isolated_truffle_project, custom_target: Optional[str], rm_target: bool
):
    os.chdir(tmp_path)
    config = {
        "ci": True,
        "confirm": True,
        "fuzz": {
            "build_directory": "build/contracts",
            "targets": ["contracts"],
            "rpc_url": "http://localhost:7545",
            "number_of_cores": 1,
            "campaign_name_prefix": "test-prefix-1",
            "api_key": "test-api-key",
            "faas_url": "https://fuzzing.diligence.tools",
        },
    }

    with open(f"{tmp_path}/.fuzz.yml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    if not custom_target:
        command = "y\n"
        custom_target = [f"{tmp_path}/contracts"]
    else:
        if rm_target:
            shutil.rmtree(f"{tmp_path}/contracts")
            command = f"{custom_target}\n"
            custom_target = [
                f"{tmp_path}/{t.strip()}" for t in custom_target.split(",")
            ]
        else:
            command = f"N\n{custom_target}\n"
            custom_target = [
                f"{tmp_path}/{t.strip()}" for t in custom_target.split(",")
            ]

    runner = CliRunner()
    result = runner.invoke(cli, ["generate-config", "--sync"], input=command)
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        result_config = yaml.load(f)
    assert result_config == {
        **config,
        "fuzz": {**config["fuzz"], "targets": custom_target},
    }
