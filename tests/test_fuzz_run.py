import json
import os
from typing import Dict, Optional
from unittest.mock import Mock, patch

import pytest
import requests
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.config import update_config
from fuzzing_cli.fuzz.exceptions import RequestError
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide import IDEArtifacts, TruffleArtifacts
from fuzzing_cli.fuzz.rpc import RPCClient
from tests.common import get_test_case, mocked_rpc_client, write_config
from tests.testdata.truffle_project.mocks import db_calls_mock

FAAS_URL = "http://localhost:9899"
ORIGINAL_SOL_CODE = "original sol code here"


def test_fuzz_run_fuzzing_lessons(
    tmp_path, bootstrapped_hardhat_fuzzing_lessons_project
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets=["contracts/LessonTestContract.sol"],
        deployed_contract_address="0xc2E17c0b175402d669Baa4DBDF3C5Ea3CF010cAC",
    )

    suggested_seed_seqs = [
        [
            {
                "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                "blockCoinbase": "0x0000000000000000000000000000000000000000",
                "blockDifficulty": "0x0",
                "blockGasLimit": "0x6691b7",
                "blockNumber": "0x2",
                "blockTime": "0x62bd7444",
                "gasLimit": "0x3381a",
                "gasPrice": "0x4a817c800",
                "input": "0x3f81a2c0000000000000000000000000000000000000000000000000000000000000002a",
                "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                "value": "0x0",
            },
            {
                "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                "blockCoinbase": "0x0000000000000000000000000000000000000000",
                "blockDifficulty": "0x0",
                "blockGasLimit": "0x6691b7",
                "blockNumber": "0x3",
                "blockTime": "0x62bd7444",
                "gasLimit": "0x6691b7",
                "gasPrice": "0x9184e72a000",
                "input": "0x9507d39abeced09521047d05b8960b7e7bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2",
                "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                "value": "0x0",
            },
        ]
    ]

    update_config(
        tmp_path.joinpath(".fuzz.yml"),
        {
            "fuzz": {
                "suggested_seed_seqs": suggested_seed_seqs,
                "lesson_description": "my lesson 1",
            }
        },
    )

    blocks = get_test_case("testdata/hardhat_fuzzing_lessons_project/lessons.json")
    codes = {
        contract["address"]: contract["deployedBytecode"]
        for contract in get_test_case(
            "testdata/hardhat_fuzzing_lessons_project/contracts.json"
        ).values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
        in result.output
    )

    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert called_with[0][0]["corpus"] == {
        "address-under-test": "0xc2E17c0b175402d669Baa4DBDF3C5Ea3CF010cAC",
        "other-addresses-under-test": None,
        "steps": [
            {
                "hash": "0x6b19d9163af45714d6fe366f686e1f53484933f0830b2ab493aa9a3cc823ce55",
                "nonce": "0x0",
                "blockHash": "0x7f192cf6f8aec7c36f369a80dd81e3823511462e3ec3191758d51fea4f5d9e82",
                "blockNumber": "0x1",
                "transactionIndex": "0x0",
                "from": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                "to": "",
                "value": "0x0",
                "gas": "0x10d79a",
                "gasPrice": "0x4a817c800",
                "input": "0x608060405234801561001057600080fd5b5061030b806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80633f81a2c01461003b5780639507d39a1461006b575b600080fd5b61005560048036038101906100509190610196565b61009b565b60405161006291906101d2565b60405180910390f35b61008560048036038101906100809190610196565b6100ec565b60405161009291906101d2565b60405180910390f35b600080826040516020016100af919061020e565b6040516020818303038152906040528051906020012060001c9050602a600080838152602001908152602001600020819055506001915050919050565b600080600080848152602001908152602001600020549050602a8103610151577fb42604cb105a16c8f6db8a41e6b00c0c1b4826465e8bc504b3eb3e88b3e6a4a060405161013990610286565b60405180910390a160006101505761014f6102a6565b5b5b6001915050919050565b600080fd5b6000819050919050565b61017381610160565b811461017e57600080fd5b50565b6000813590506101908161016a565b92915050565b6000602082840312156101ac576101ab61015b565b5b60006101ba84828501610181565b91505092915050565b6101cc81610160565b82525050565b60006020820190506101e760008301846101c3565b92915050565b6000819050919050565b61020861020382610160565b6101ed565b82525050565b600061021a82846101f7565b60208201915081905092915050565b600082825260208201905092915050565b7f696e206765740000000000000000000000000000000000000000000000000000600082015250565b6000610270600683610229565b915061027b8261023a565b602082019050919050565b6000602082019050818103600083015261029f81610263565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052600160045260246000fdfea264697066735822122074b031fbc0383005b2a7a3aa6559e993b812dd2ff24fbce8a172ec014f494bfc64736f6c634300080f0033",
                "v": "0x25",
                "r": "0x210f089fadd7f0848792ed9d0a0d5050cbc6fb120d714a82e89b4679fdc4163d",
                "s": "0x2f864625e045fc0e11c188eeec22a050e650be538c540a7ba100b2c00302289c",
            }
        ],
        "suggested-seed-seqs": suggested_seed_seqs,
    }


@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("bootstrapped_hardhat_project"),
        lazy_fixture("bootstrapped_truffle_project"),
        lazy_fixture("bootstrapped_brownie_project"),
        lazy_fixture("bootstrapped_dapptools_project"),
    ],
)
@pytest.mark.parametrize("absolute_targets", [True, False])
@pytest.mark.parametrize("absolute_build_dir", [True, False])
@pytest.mark.parametrize("absolute_sources_dir", [True, False])
@pytest.mark.parametrize("folder_target", [True, False])
def test_fuzz(
    tmp_path,
    ide: Dict[str, any],
    absolute_targets: bool,
    absolute_build_dir: bool,
    absolute_sources_dir: bool,
    folder_target: bool,
):
    if not folder_target:
        write_config(
            config_path=f"{tmp_path}/.fuzz.yml",
            base_path=str(tmp_path),
            absolute_targets=absolute_targets,
            absolute_build_directory=absolute_build_dir,
            absolute_sources_directory=absolute_sources_dir,
            **ide,
        )
    else:
        write_config(
            config_path=f"{tmp_path}/.fuzz.yml",
            base_path=str(tmp_path),
            absolute_targets=absolute_targets,
            absolute_build_directory=absolute_build_dir,
            absolute_sources_directory=absolute_sources_dir,
            **{**ide, "targets": [ide["sources_directory"]]},
        )

    IDE_NAME = ide["ide"]

    blocks = get_test_case(f"testdata/{IDE_NAME}_project/blocks.json")
    contracts = get_test_case(f"testdata/{IDE_NAME}_project/contracts.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch.object(  # for truffle project only
        TruffleArtifacts,
        "query_truffle_db",
        new=Mock(side_effect=db_calls_mock(contracts, str(tmp_path))),
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
        in result.output
    )

    start_faas_campaign_mock.assert_called_once()
    payload = start_faas_campaign_mock.call_args[0][0]

    processed_payload = get_test_case(
        f"testdata/{IDE_NAME}_project/processed_payload.json"
    )
    # we need this because the truffle uses absolute paths in artifacts
    # and there's no way to hardcode `tmp_path` related paths
    if IDE_NAME == "truffle":
        processed_payload["sources"] = {
            name.replace("artifacts", str(tmp_path)): data
            for name, data in processed_payload["sources"].items()
        }
        processed_payload["contracts"] = [
            {
                **c,
                "mainSourceFile": c["mainSourceFile"].replace(
                    "artifacts", str(tmp_path)
                ),
                "sourcePaths": {
                    k: v.replace("artifacts", str(tmp_path))
                    for k, v in c["sourcePaths"].items()
                },
            }
            for c in processed_payload["contracts"]
        ]

    assert payload["parameters"] == processed_payload["parameters"]
    assert payload["corpus"] == processed_payload["corpus"]
    assert payload["contracts"] == processed_payload["contracts"]
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"


@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("bootstrapped_hardhat_project"),
        lazy_fixture("bootstrapped_truffle_project"),
        lazy_fixture("bootstrapped_brownie_project"),
        lazy_fixture("bootstrapped_dapptools_project"),
    ],
)
def test_fuzz_empty_artifacts(tmp_path, ide: Dict[str, any]):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**ide, "build_directory": "wrong_directory"},
    )
    os.makedirs(tmp_path.joinpath("wrong_directory"))

    IDE_NAME = ide["ide"]

    blocks = get_test_case(f"testdata/{IDE_NAME}_project/blocks.json")
    contracts = get_test_case(f"testdata/{IDE_NAME}_project/contracts.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch.object(  # for truffle project only
        TruffleArtifacts,
        "query_truffle_db",
        new=Mock(side_effect=db_calls_mock(contracts, str(tmp_path))),
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 2
    assert (
        f"Error: No contract being submitted. "
        f"Please check your config (hint: build_directory path or targets paths)\n"
        in result.output
    )

    start_faas_campaign_mock.assert_not_called()


@pytest.mark.parametrize("ide", [lazy_fixture("bootstrapped_hardhat_project")])
@pytest.mark.parametrize(
    "corpus_target", [None, "cmp_9e931b147e7143a8b53041c708d5474e"]
)
def test_fuzz_corpus_target(
    tmp_path, ide: Dict[str, any], corpus_target: Optional[str]
):
    write_config(config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **ide)

    IDE_NAME = ide["ide"]
    blocks = get_test_case(f"testdata/{IDE_NAME}_project/blocks.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in get_test_case(
            f"testdata/{IDE_NAME}_project/contracts.json"
        ).values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        cmd = ["run"]
        if corpus_target:
            cmd.extend(["--corpus-target", corpus_target])
        result = runner.invoke(cli, cmd)

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
        in result.output
    )

    start_faas_campaign_mock.assert_called_once()
    payload = start_faas_campaign_mock.call_args[0][0]

    assert payload["corpus"].get("target", None) == corpus_target


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
