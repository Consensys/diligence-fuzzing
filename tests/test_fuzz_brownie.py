import json
from unittest.mock import patch

import pytest
import requests
from click.testing import CliRunner
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.exceptions import RequestError
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc import RPCClient

from .common import get_test_case, write_config

FAAS_URL = "http://localhost:9899"
ORIGINAL_SOL_CODE = "original sol code here"


def test_fuzz_no_build_dir(tmp_path):
    runner = CliRunner()
    write_config(not_include=["build_directory"])

    result = runner.invoke(cli, ["run", "contracts"])
    assert (
        "Build directory not provided. You need to set the `build_directory`"
        in result.output
    )
    assert result.exit_code != 0


def test_fuzz_no_deployed_address(tmp_path):
    runner = CliRunner()
    write_config(not_include=["deployed_contract_address"])

    result = runner.invoke(cli, ["run", "contracts"])
    assert (
        "Deployed contract address not provided. You need to provide an address"
        in result.output
    )
    assert result.exit_code != 0


def test_fuzz_no_target(tmp_path):
    runner = CliRunner()
    write_config(not_include=["targets"])

    result = runner.invoke(cli, ["run"])
    assert "Error: Target not provided." in result.output
    assert result.exit_code != 0


def test_fuzz_no_contract_at_address(tmp_path, brownie_project):
    write_config(
        base_path=str(tmp_path),
        deployed_contract_address="0x1111646075fa72737e1F6114654C5d9949a6aaaa",
    )

    with patch.object(RPCClient, "get_code") as get_code_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        get_code_mock.return_value = None

        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert (
        "Error: Unable to find contracts deployed at 0x1111646075fa72737e1F6114654C5d9949a6aaaa"
        in result.output
    )
    assert result.exit_code != 0


def test_faas_not_running(tmp_path, brownie_project):
    write_config(base_path=str(tmp_path))

    with patch.object(RPCClient, "get_code") as get_code_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_code_mock.return_value = "0x1"
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        start_faas_campaign_mock.side_effect = RequestError(
            f"Error starting FaaS campaign."
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert "RequestError: Error starting FaaS campaign" in result.output
    assert result.exit_code != 0


def test_faas_target_config_file(tmp_path, brownie_project):
    """Here we reuse the test_faas_not_running logic to check that the target is being read
    from the config file. This is possible because the faas not running error is triggered
    after the Target check. If the target was not available, a different error would be thrown
    and the test would fail"""
    write_config(base_path=str(tmp_path))

    with patch.object(RPCClient, "get_code") as get_code_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        get_code_mock.return_value = "0x1"
        start_faas_campaign_mock.side_effect = RequestError(
            f"Error starting FaaS campaign."
        )

        runner = CliRunner()
        # we call the run command without the target parameter.
        result = runner.invoke(cli, ["run"])

    assert "RequestError: Error starting FaaS campaign." in result.output
    assert result.exit_code != 0


def test_rpc_not_running(tmp_path):
    write_config(base_path=str(tmp_path))

    with patch.object(requests, "request") as requests_mock:
        requests_mock.side_effect = RequestException()

        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert (
        "HTTP error calling RPC method eth_getBlockByNumber with parameters"
        in result.output
    )
    assert result.exit_code != 0


def test_fuzz_run(tmp_path, brownie_project):
    write_config(base_path=str(tmp_path))

    with patch.object(RPCClient, "get_code") as get_code_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        get_code_mock.return_value = "0x1"
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    request_payload = json.dumps(called_with[0])

    keywords = [
        "parameters",
        "name",
        "corpus",
        "sources",
        "contracts",
        "address-under-test",
        "source",
        "fileIndex",
        "sourcePaths",
        "deployedSourceMap",
        "mainSourceFile",
        "contractName",
        "bytecode",
        "deployedBytecode",
        "sourceMap",
        "deployedSourceMap",
    ]

    for keyword in keywords:
        assert keyword in request_payload

    assert result.exit_code == 0


def test_fuzz_run_map_to_original_source(tmp_path, brownie_project):
    write_config(base_path=str(tmp_path))

    with patch.object(RPCClient, "get_code") as get_code_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        get_code_mock.return_value = "0x1"
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", "--map-to-original-source", f"{tmp_path}/contracts"]
        )

    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    request_payload = json.dumps(called_with[0])

    assert ORIGINAL_SOL_CODE in request_payload

    keywords = [
        "parameters",
        "name",
        "corpus",
        "sources",
        "contracts",
        "address-under-test",
        "source",
        "fileIndex",
        "sourcePaths",
        "deployedSourceMap",
        "mainSourceFile",
        "contractName",
        "bytecode",
        "deployedBytecode",
        "sourceMap",
        "deployedSourceMap",
    ]

    for keyword in keywords:
        assert keyword in request_payload

    assert result.exit_code == 0


@pytest.mark.parametrize("keyword", ("run", "disarm", "arm", "run"))
def test_fuzz_subcommands_present(keyword):
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])

    assert keyword in result.output


@patch("fuzzing_cli.fuzz.scribble.ScribbleMixin.instrument_solc_in_place")
def test_fuzz_arm(mock, tmp_path, brownie_project):
    runner = CliRunner()
    result = runner.invoke(cli, ["arm", f"{tmp_path}/contracts/sample.sol"])

    mock.assert_called()
    mock.assert_called_with(
        file_list=(f"{tmp_path}/contracts/sample.sol",),
        scribble_path="scribble",
        remappings=[],
        solc_version=None,
        no_assert=False,
    )
    assert result.exit_code == 0


@patch("fuzzing_cli.fuzz.scribble.ScribbleMixin.instrument_solc_in_place")
def test_fuzz_arm_no_assert(mock, tmp_path, brownie_project):
    runner = CliRunner()
    result = runner.invoke(
        cli, ["arm", "--no-assert", f"{tmp_path}/contracts/sample.sol"]
    )

    mock.assert_called()
    mock.assert_called_with(
        file_list=(f"{tmp_path}/contracts/sample.sol",),
        scribble_path="scribble",
        remappings=[],
        solc_version=None,
        no_assert=True,
    )
    assert result.exit_code == 0


@patch("fuzzing_cli.fuzz.scribble.ScribbleMixin.disarm_solc_in_place")
def test_fuzz_disarm(mock, tmp_path, brownie_project):
    runner = CliRunner()
    result = runner.invoke(cli, ["disarm", f"{tmp_path}/contracts/sample.sol"])

    mock.assert_called()
    mock.assert_called_with(
        file_list=(f"{tmp_path}/contracts/sample.sol",),
        scribble_path="scribble",
        remappings=[],
        solc_version=None,
    )
    assert result.exit_code == 0
