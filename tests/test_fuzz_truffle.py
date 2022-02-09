import json
import os
from typing import Dict
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide.truffle import TruffleArtifacts
from fuzzing_cli.fuzz.rpc import RPCClient

from .common import get_test_case, write_config

FAAS_URL = "http://localhost:9899"


@pytest.mark.parametrize("absolute_target", [True, False])
@pytest.mark.parametrize("truffle_project", [False, True], indirect=True)
def test_fuzz_run(tmp_path, truffle_project: Dict[str, any], absolute_target):
    if not absolute_target and not truffle_project["switch_dir"]:
        pytest.skip(
            "absolute_target=False, truffle_project=False through parametrization"
        )

    write_config(
        base_path=str(tmp_path),
        not_include=["api_key"],
        targets="contracts/MasterChefV2.sol",
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        TruffleArtifacts, "query_truffle_db"
    ) as query_truffle_db_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        query_truffle_db_mock.side_effect = [
            {"projectId": "test-project"},
            {
                "project": {
                    "contracts": [
                        {
                            "name": "Foo",
                            "compilation": {
                                "processedSources": [
                                    {
                                        "source": {
                                            "sourcePath": f"{tmp_path}/contracts/sample.sol"
                                        }
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        ]

        runner = CliRunner()
        target = (
            f"{tmp_path}/contracts/sample.sol"
            if absolute_target
            else "contracts/sample.sol"
        )
        cwd = os.getcwd()
        result = runner.invoke(cli, ["run", target, "--api-key", "test"])

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


def test_fuzz_run_corpus_target(tmp_path, truffle_project):
    write_config(base_path=str(tmp_path), targets="contracts/MasterChefV2.sol")

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        TruffleArtifacts, "query_truffle_db"
    ) as query_truffle_db_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        query_truffle_db_mock.side_effect = [
            {"projectId": "test-project"},
            {
                "project": {
                    "contracts": [
                        {
                            "name": "Foo",
                            "compilation": {
                                "processedSources": [
                                    {
                                        "source": {
                                            "sourcePath": f"{tmp_path}/contracts/sample.sol"
                                        }
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        ]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/sample.sol",
                "-c",
                "prj_639cffb2a3e0407fbe2c701caaf5ab33",
            ],
        )

    contract_exists_mock.assert_not_called()
    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    assert called_with[0][0]["corpus"] == {
        "address-under-test": "0x7277646075fa72737e1F6114654C5d9949a67dF2",
        "other-addresses-under-test": None,
        "steps": [
            {
                "blockHash": "0x12effde2c3cb82e381e7e4232d3bf810920df83710faf07940a1c510a96d1740",
                "blockNumber": "0x1",
                "from": "0xe6559ce865436c9206c6a971ed34658a57e51f17",
                "gas": "0x6691b7",
                "gasPrice": "0x0",
                "hash": "0x5b2213faa860f042be3d68c782ee5a1f45aea9505f874a1370a0c3163e13f3f8",
                "input": "0x608060405234801561001057600080fd5b506101c8806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063b0a378b01461003b578063df5b722714610055575b600080fd5b610043610076565b60408051918252519081900360200190f35b6100746004803603602081101561006b57600080fd5b503515156100e7565b005b6000610080610109565b90506000546013146100e457604080516020808252601390820152720c0e88151a1a5cc81cda1bdd5b190819985a5b606a1b8183015290517fb42604cb105a16c8f6db8a41e6b00c0c1b4826465e8bc504b3eb3e88b3e6a4a09181900360600190a1fe5b90565b806100f35760006100f6565b60015b60ff166000546002020160008190555050565b60008054600a141561011757fe5b600054601e141561012457fe5b6000546032141561013157fe5b6000546046141561013e57fe5b600054605a141561014b57fe5b600054606e141561015857fe5b6000546082141561016557fe5b6000546096141561017257fe5b60005460aa141561017f57fe5b60005460be141561018c57fe5b5060009056fea2646970667358221220d15c0974595ed5c9a5da68377d16635bfa92f13a2af22bf0b52f63632505f04664736f6c634300060c0033",
                "nonce": "0x0",
                "r": "0x8cb33aaf88705ef9b626e3b641c356c50c478912fb02ccddef9ab053fc83827b",
                "s": "0x62e58b06e7c1decaedbdb8bfcdbddf69c56c5bfce6f27187ac587492686efd77",
                "to": "",
                "transactionIndex": "0x0",
                "v": "0x25",
                "value": "0x0",
            }
        ],
        "target": "prj_639cffb2a3e0407fbe2c701caaf5ab33",
    }

    assert result.exit_code == 0
