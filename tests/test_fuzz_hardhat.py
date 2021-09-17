import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mythx_cli.cli import cli
from mythx_cli.fuzz.faas import FaasClient
from mythx_cli.fuzz.rpc import RPCClient

from .common import get_test_case, write_config

FAAS_URL = "http://localhost:9899"


@pytest.mark.parametrize("absolute_target", [True, False])
@pytest.mark.parametrize("hardhat_project", [False, True], indirect=True)
def test_fuzz_run(tmp_path, hardhat_project, absolute_target):
    if not absolute_target and not hardhat_project["switch_dir"]:
        pytest.skip(
            "absolute_target=False, hardhat_project=False through parametrization"
        )

    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        target = (
            f"{tmp_path}/contracts/MasterChefV2.sol"
            if absolute_target
            else "contracts/MasterChefV2.sol"
        )
        result = runner.invoke(cli, ["run", target])

    contract_exists_mock.assert_called_with(
        "0x7277646075fa72737e1F6114654C5d9949a67dF2"
    )
    contract_exists_mock.assert_called_once()
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


def test_fuzz_run_corpus_target(tmp_path, hardhat_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-c",
                "prj_639cffb2a3e0407fbe2c701caaf5ab33",
            ],
        )

    contract_exists_mock.assert_not_called()
    get_all_blocks_mock.assert_not_called()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    assert called_with[0][0]["corpus"] == {
        "target": "prj_639cffb2a3e0407fbe2c701caaf5ab33"
    }

    assert result.exit_code == 0
