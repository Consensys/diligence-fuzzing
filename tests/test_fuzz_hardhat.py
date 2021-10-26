from copy import deepcopy
from operator import itemgetter
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc import RPCClient

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
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name"
    ) as generate_campaign_name_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        generate_campaign_name_mock.return_value = "test_campaign_1"

        runner = CliRunner()
        target = f"{tmp_path}/contracts" if absolute_target else "contracts"
        result = runner.invoke(cli, ["run", target])

    assert result.exit_code == 0
    contract_exists_mock.assert_called_with(
        "0x7277646075fa72737e1F6114654C5d9949a67dF2"
    )
    contract_exists_mock.assert_called_once()
    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    called_with = deepcopy(start_faas_campaign_mock.call_args[0][0])
    sorted_contracts = sorted(called_with["contracts"], key=itemgetter("contractName"))
    called_with["contracts"] = sorted_contracts

    assert called_with == {
        "parameters": {
            "discovery-probability-threshold": 0.0,
            "num-cores": 1,
            "assertion-checking-mode": 1,
        },
        "name": "test_campaign_1",
        "corpus": {
            "address-under-test": "0x7277646075fa72737e1F6114654C5d9949a67dF2",
            "steps": [
                {
                    "hash": "0x5b2213faa860f042be3d68c782ee5a1f45aea9505f874a1370a0c3163e13f3f8",
                    "nonce": "0x0",
                    "blockHash": "0x12effde2c3cb82e381e7e4232d3bf810920df83710faf07940a1c510a96d1740",
                    "blockNumber": "0x1",
                    "transactionIndex": "0x0",
                    "from": "0xe6559ce865436c9206c6a971ed34658a57e51f17",
                    "to": "",
                    "value": "0x0",
                    "gas": "0x6691b7",
                    "gasPrice": "0x0",
                    "input": "0x608060405234801561001057600080fd5b506101c8806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063b0a378b01461003b578063df5b722714610055575b600080fd5b610043610076565b60408051918252519081900360200190f35b6100746004803603602081101561006b57600080fd5b503515156100e7565b005b6000610080610109565b90506000546013146100e457604080516020808252601390820152720c0e88151a1a5cc81cda1bdd5b190819985a5b606a1b8183015290517fb42604cb105a16c8f6db8a41e6b00c0c1b4826465e8bc504b3eb3e88b3e6a4a09181900360600190a1fe5b90565b806100f35760006100f6565b60015b60ff166000546002020160008190555050565b60008054600a141561011757fe5b600054601e141561012457fe5b6000546032141561013157fe5b6000546046141561013e57fe5b600054605a141561014b57fe5b600054606e141561015857fe5b6000546082141561016557fe5b6000546096141561017257fe5b60005460aa141561017f57fe5b60005460be141561018c57fe5b5060009056fea2646970667358221220d15c0974595ed5c9a5da68377d16635bfa92f13a2af22bf0b52f63632505f04664736f6c634300060c0033",
                    "v": "0x25",
                    "r": "0x8cb33aaf88705ef9b626e3b641c356c50c478912fb02ccddef9ab053fc83827b",
                    "s": "0x62e58b06e7c1decaedbdb8bfcdbddf69c56c5bfce6f27187ac587492686efd77",
                }
            ],
            "other-addresses-under-test": None,
        },
        "sources": {
            "contracts/sample.sol": {
                "fileIndex": 0,
                "source": "sample source",
                "ast": {
                    "absolutePath": "contracts/sample.sol",
                    "exportedSymbols": {"Bar": [8]},
                    "id": 9,
                    "nodeType": "SourceUnit",
                    "nodes": [],
                    "src": "0:75:0",
                },
            },
            "contracts/MasterChefV2.sol": {
                "fileIndex": 5,
                "source": "sample source",
                "ast": {
                    "absolutePath": "contracts/MasterChefV2.sol",
                    "exportedSymbols": {"IMigratorChef": [858], "MasterChefV2": [2091]},
                    "id": 2092,
                    "license": "MIT",
                    "nodeType": "SourceUnit",
                    "nodes": [],
                    "src": "33:15037:5",
                },
            },
        },
        "contracts": [
            {
                "sourcePaths": {0: "contracts/sample.sol"},
                "deployedSourceMap": "0:74:0:-:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;41:31;;;;;;:::o",
                "deployedBytecode": "6080604052348015600f576000",
                "sourceMap": "0:74:0:-:0;;;;;;;;;;;;;;;;;;;",
                "bytecode": "6080604052348015600f57",
                "contractName": "Bar",
                "mainSourceFile": "contracts/sample.sol",
            },
            {
                "sourcePaths": {0: "contracts/sample.sol"},
                "deployedSourceMap": "0:74:0:-:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;41:31;:::o",
                "deployedBytecode": "6080604052348015600f57600080f",
                "sourceMap": "0:74:0:-:0;;;;;;;;;;;;;;;;;;;",
                "bytecode": "6080604052348015600f57600080",
                "contractName": "Foo",
                "mainSourceFile": "contracts/sample.sol",
            },
            {
                "sourcePaths": {
                    0: "contracts/contract-1.sol",
                    1: "contracts/contract-2.sol",
                    2: "contracts/contract-3.sol",
                    3: "contracts/contract-4.sol",
                    4: "contracts/contract-5.sol",
                    5: "contracts/MasterChefV2.sol",
                },
                "deployedSourceMap": "1098:13971:5:-:0;774:472:1;-1:-1:-1",
                "deployedBytecode": "6080604052600436106101d85760003560e01c806361621aaa",
                "sourceMap": "1098:13971:5:-:0;;;3839:182;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::i;:::-;639:5:1;:18;;-1:-1:-1;;;;;",
                "bytecode": "60e06040523480156200001157600080fd5b5060405162",
                "contractName": "MasterChefV2",
                "mainSourceFile": "contracts/MasterChefV2.sol",
            },
        ],
        "project": None,
    }


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
