import os
from pathlib import Path
from typing import List, Optional
from unittest.mock import Mock, patch

import click
import inquirer
import pytest
import yaml
from click import style
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.config.generate import (
    QM,
    determine_build_dir,
    determine_campaign_name,
    determine_cpu_cores,
    determine_ide,
    determine_rpc_url,
    determine_sources_dir,
    determine_targets,
)
from fuzzing_cli.fuzz.config.utils import parse_config

UP = "\x1b\x5b\x41"
DOWN = "\x1b\x5b\x42"
LEFT = "\x1b\x5b\x44"
RIGHT = "\x1b\x5b\x43"


def test_generate_config(tmp_path, hardhat_project):
    os.chdir(tmp_path)
    actions = ["y", "n", "y", "n", "y", "http://localhost:1111/", "4", "\n"]
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "generate"], input="\n".join(actions))
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    assert config == {
        "analyze": None,
        "fuzz": {
            "ide": "hardhat",
            "quick_check": False,
            "build_directory": str(Path(tmp_path).joinpath("artifacts")),
            "sources_directory": str(Path(tmp_path).joinpath("contracts")),
            "targets": [str(Path(tmp_path).joinpath("contracts"))],
            "rpc_url": "http://localhost:1111/",
            "smart_mode": False,
            "number_of_cores": 4,
            "campaign_name_prefix": Path(tmp_path).name.lower().replace("-", "_"),
            "quick_check": False,
        },
    }


def test_generate_config_smart_mode(tmp_path, hardhat_project):
    os.chdir(tmp_path)
    actions = ["y", "y", "http://localhost:1111/", "4", "\n"]
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "generate"], input="\n".join(actions))
    assert result.exit_code == 0
    with open(Path(tmp_path).joinpath(".fuzz.yml"), "r") as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    assert config == {
        "analyze": None,
        "fuzz": {
            "ide": "hardhat",
            "quick_check": False,
            "rpc_url": "http://localhost:1111/",
            "smart_mode": True,
            "number_of_cores": 4,
            "campaign_name_prefix": Path(tmp_path).name.lower().replace("-", "_"),
            "quick_check": False,
        },
    }


def test_sync_without_config(tmp_path):
    os.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "generate", "--sync", "sample.yml"])
    assert result.exit_code == 2
    assert f"⚠️  Config file sample.yml does not exist" in result.output


@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("truffle_project"),
        lazy_fixture("brownie_project"),
        lazy_fixture("hardhat_project"),
        lazy_fixture("dapptools_project"),
        lazy_fixture("foundry_project"),
    ],
)
@patch(
    "fuzzing_cli.fuzz.config.generate.determine_targets",
    new=Mock(return_value=["test1.sol", "test2.sol"]),
)
def test_syncing(tmp_path, ide):
    config = {
        "fuzz": {
            "build_directory": "build/contracts",
            "targets": ["contracts"],
            "rpc_url": "http://localhost:7545",
            "number_of_cores": 1,
            "campaign_name_prefix": "test-prefix-1",
            "key": "test-api-key",
            "faas_url": "https://fuzzing.diligence.tools",
        }
    }

    with open(f"{tmp_path}/.fuzz.yml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    runner = CliRunner()
    result = runner.invoke(cli, ["config", "generate", "--sync"])
    assert result.exit_code == 0

    updated_config = parse_config(Path(tmp_path).joinpath(".fuzz.yml"))
    assert updated_config == {
        **config,
        "fuzz": {**config["fuzz"], "targets": ["test1.sol", "test2.sol"]},
    }


@pytest.mark.parametrize(
    "ide, ide_name",
    [
        (lazy_fixture("truffle_project"), "Truffle"),
        (lazy_fixture("brownie_project"), "Brownie"),
        (lazy_fixture("hardhat_project"), "Hardhat"),
        (lazy_fixture("dapptools_project"), "Dapptools"),
        (lazy_fixture("foundry_project"), "Foundry"),
    ],
)
@pytest.mark.parametrize("confirm_ide", [True, False])
def test_determine_ide_confirm(ide, ide_name: str, confirm_ide: bool):
    with patch.object(inquirer, "prompt") as inquirer_prompt, patch.object(
        click, "confirm"
    ) as click_confirm:
        click_confirm.return_value = True
        ide = determine_ide(confirm_ide)

        inquirer_prompt.assert_not_called()
        if not confirm_ide:
            click_confirm.assert_called_once_with(
                f"{QM} You seem to be using {ide_name}, is that correct?", default=True
            )
        else:
            click_confirm.assert_not_called()

    assert ide == ide_name.lower()


@pytest.mark.parametrize("ide", [lazy_fixture("truffle_project"), None])
def test_determine_ide_not_confirmed(ide):
    with patch.object(inquirer, "prompt") as inquirer_prompt, patch.object(
        inquirer, "List"
    ) as inquirer_list, patch.object(click, "confirm") as click_confirm:
        click_confirm.return_value = False
        inquirer_prompt.return_value = {"ide": "Hardhat"}
        inquirer_list.return_value = "<Mocked List>"
        ide = determine_ide()

        inquirer_prompt.assert_called_once_with(["<Mocked List>"])
        inquirer_list.assert_called_once_with(
            "ide",
            message="Please select IDE",
            choices=["Truffle", "Hardhat", "Brownie", "Dapptools", "Foundry"],
        )
        if ide:
            click_confirm.assert_called_once_with(
                f"{QM} You seem to be using Truffle, is that correct?", default=True
            )
        else:
            click_confirm.assert_not_called()

    assert ide == "hardhat"


def test_determine_targets(tmp_path, truffle_project):
    with patch.object(inquirer, "prompt") as inquirer_prompt, patch.object(
        click, "confirm"
    ) as click_confirm:
        click_confirm.side_effect = [True, False]
        targets = determine_targets("truffle")
        inquirer_prompt.assert_not_called()
        assert click_confirm.call_count == 2
        assert click_confirm.call_args_list[0][0] == (
            f"{QM} Is {style(f'{tmp_path}/contracts', fg='yellow')} correct directory to fuzz contracts from?",
        )
        assert click_confirm.call_args_list[1][0] == (
            f"{QM} Directories contain source files. Do you want to select them individually?",
        )

    assert targets == [f"{tmp_path}/contracts"]


@pytest.mark.parametrize(
    "targets_return", [["contracts/Foo.sol", "contracts/Bar.sol"], [], None]
)
@pytest.mark.parametrize(
    "custom_targets",
    ["contracts, contracts/Migrations.sol, contracts/ABC.sol, /test.sol", None],
)
def test_determine_targets_manual_targets_selection(
    tmp_path: Path,
    truffle_project,
    targets_return: Optional[List[str]],
    custom_targets: Optional[str],
):
    custom_targets_processed = (
        [
            t.strip() if t.strip().startswith("/") else f"{tmp_path}/{t.strip()}"
            for t in custom_targets.split(",")
        ]
        if custom_targets
        else []
    )

    with patch.object(inquirer, "prompt") as inquirer_prompt, patch.object(
        click, "confirm"
    ) as click_confirm, patch.object(
        inquirer, "Checkbox"
    ) as inquirer_checkbox, patch.object(
        click, "secho"
    ) as click_secho, patch.object(
        click, "prompt"
    ) as click_prompt:
        click_confirm.side_effect = [False if custom_targets else True, True]
        click_prompt.return_value = custom_targets
        inquirer_prompt.return_value = {
            "targets": [f"{tmp_path}/{t}" for t in (targets_return or [])]
        }
        inquirer_checkbox.return_value = "<Mocked Checkbox>"

        targets = determine_targets("truffle")
        inquirer_prompt.assert_called_once_with(["<Mocked Checkbox>"])
        inquirer_checkbox.assert_called_once_with(
            "targets",
            message="Please select target files (SPACE to select, RETURN to finish)",
            choices=[
                ("contracts/ABC.sol", f"{tmp_path}/contracts/ABC.sol"),
                ("contracts/Bar.sol", f"{tmp_path}/contracts/Bar.sol"),
                ("contracts/Foo.sol", f"{tmp_path}/contracts/Foo.sol"),
                ("contracts/Migrations.sol", f"{tmp_path}/contracts/Migrations.sol"),
            ],
        )
        assert click_confirm.call_count == 2
        assert click_confirm.call_args_list[0][0] == (
            f"{QM} Is {style(f'{tmp_path}/contracts', fg='yellow')} correct directory to fuzz contracts from?",
        )
        assert click_confirm.call_args_list[1][0] == (
            f"{QM} Directories contain source files. Do you want to select them individually?",
        )
        if custom_targets:
            click_prompt.assert_called_once_with(
                f"{QM} Specify folder(s) or smart-contract(s) (comma-separated) to fuzz"
            )
        else:
            click_prompt.assert_not_called()

        if not targets_return:
            click_secho.assert_called_once_with(
                "⚠️  No targets are selected, please configure them manually in a config file"
            )
        else:
            click_secho.assert_not_called()

        assert targets == [f"{tmp_path}/{t}" for t in (targets_return or [])] + [
            t for t in custom_targets_processed if t.endswith(".sol")
        ]


@patch("pathlib.Path.exists", new=Mock(return_value=False))
@pytest.mark.parametrize("custom_dir", [True, False])
def test_determine_targets_source_dir_not_exists(
    tmp_path, truffle_project, custom_dir: bool
):
    with patch.object(click, "confirm") as click_confirm, patch.object(
        click, "prompt"
    ) as click_prompt:
        click_confirm.side_effect = [custom_dir, False]
        click_prompt.return_value = f"{tmp_path}/contracts"

        targets = determine_targets("truffle")

        assert click_confirm.call_count == 2
        assert click_confirm.call_args_list[0][0] == (
            f"{QM} We couldn't find any contracts at {style(f'{tmp_path}/contracts', fg='yellow')}. "
            f"Have you configured a custom contracts sources directory?",
        )
        assert click_confirm.call_args_list[1][0] == (
            f"{QM} Directories contain source files. Do you want to select them individually?",
        )

        if custom_dir:
            click_prompt.assert_called_once_with(
                f"{QM} Specify folder(s) or smart-contract(s) (comma-separated) to fuzz"
            )
        else:
            click_prompt.assert_not_called()

        assert targets == [f"{tmp_path}/contracts"]


@pytest.mark.parametrize("custom_build_dir", ["build_test", None])
@pytest.mark.parametrize("build_dir_exists", [True, False])
@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("truffle_project"),
        lazy_fixture("brownie_project"),
        lazy_fixture("hardhat_project"),
        lazy_fixture("dapptools_project"),
        lazy_fixture("foundry_project"),
    ],
)
def test_determine_build_dir(
    tmp_path, ide, custom_build_dir: Optional[str], build_dir_exists: bool
):
    with patch.object(click, "confirm") as click_confirm, patch.object(
        click, "prompt"
    ) as click_prompt, patch("pathlib.Path.exists") as path_exists:
        path_exists.return_value = build_dir_exists
        click_confirm.return_value = False if custom_build_dir else True
        if not build_dir_exists:
            click_confirm.return_value = not click_confirm.return_value
        click_prompt.return_value = custom_build_dir

        build_dir = determine_build_dir(ide["ide"])

        bds = style(f'{tmp_path}/{ide["build_directory"]}', fg="yellow")
        assert click_confirm.call_count == 1
        assert click_confirm.call_args_list[0][0] == (
            f"{QM} Is {bds} correct build directory for the project?"
            if build_dir_exists
            else f"{QM} We couldn't find build directory at {bds}. Have you configured a custom build directory?",
        )

        if custom_build_dir:
            click_prompt.assert_called_once_with(f"{QM} Specify build directory path")
        else:
            click_prompt.assert_not_called()

        assert (
            build_dir == f"{tmp_path}/{custom_build_dir}"
            if custom_build_dir
            else f"{tmp_path}/{ide['build_directory']}"
        )


def test_determine_rpc_url(tmp_path, truffle_project):
    with patch.object(click, "prompt") as click_prompt:
        click_prompt.return_value = "http://localhost:7777"
        rpc_url = determine_rpc_url()
        click_prompt.assert_called_once_with(
            f"{QM} Specify RPC URL to get seed state from (e.g. local Ganache instance)",
            default="http://localhost:8545",
        )
    assert rpc_url == "http://localhost:7777"


def test_determine_cpu_cores(tmp_path: Path, truffle_project):
    with patch.object(click, "prompt") as click_prompt:
        click_prompt.return_value = 4
        cores = determine_cpu_cores()
        assert click_prompt.call_count == 1
        assert click_prompt.call_args_list[0][0] == (
            f"{QM} Specify CPU cores (1-4) to be used for fuzzing",
        )

    assert cores == 4


def test_determine_campaign_name(tmp_path: Path, truffle_project):
    with patch.object(click, "prompt") as click_prompt:
        click_prompt.return_value = "test-1"

        campaign_name = determine_campaign_name()

        click_prompt.assert_called_once_with(
            f"{QM} Now set fuzzing campaign name prefix",
            default=tmp_path.name.lower().replace("-", "_"),
            show_default=True,
        )

    assert campaign_name == "test-1"


def test_determine_sources_dir(tmp_path, truffle_project):
    assert determine_sources_dir([]) is None
    assert determine_sources_dir([str(tmp_path.joinpath("contracts"))]) == str(
        tmp_path.joinpath("contracts")
    )
    assert determine_sources_dir(
        [str(tmp_path.joinpath("contracts", "ABC.sol"))]
    ) == str(tmp_path.joinpath("contracts"))
    assert determine_sources_dir(
        [
            str(tmp_path.joinpath("contracts")),
            str(tmp_path.joinpath("contracts", "Foo.sol")),
            str(tmp_path.joinpath("contracts", "ABC.sol")),
        ]
    ) == str(tmp_path.joinpath("contracts"))
    assert determine_sources_dir(
        [
            str(tmp_path.joinpath("contracts", "Foo.sol")),
            str(tmp_path.joinpath("contracts", "Bar.sol")),
        ]
    ) == str(tmp_path.joinpath("contracts"))
