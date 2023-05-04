import json
import os
from typing import Dict, Mapping, Optional, Union
from unittest.mock import Mock, patch

import pytest
import requests
import requests_mock
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide import TruffleArtifacts
from fuzzing_cli.fuzz.scribble import SCRIBBLE_ARMING_META_FILE
from tests.common import (
    assert_is_equal,
    get_python_version,
    get_test_case,
    mocked_rpc_client,
    write_config,
)
from tests.testdata.truffle_project.mocks import db_calls_mock

FAAS_URL = "http://localhost:9899"
ORIGINAL_SOL_CODE = "original sol code here"


suggested_seed_seqs = [
    [
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
    ],
    [
        [
            {
                "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                "blockCoinbase": "0x0000000000000000000000000000000000000000",
                "blockDifficulty": "0x0",
                "blockGasLimit": "0x6691b7",
                "blockNumber": "0x4",
                "blockTime": "0x62bd7444",
                "gasLimit": "0x3381a",
                "gasPrice": "0x4a817c800",
                "input": "0x3f81a2c0000000000000000000000000000000000000000000000000000000000000002a",
                "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                "value": "0x0",
            }
        ],
        [
            {
                "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                "blockCoinbase": "0x0000000000000000000000000000000000000000",
                "blockDifficulty": "0x0",
                "blockGasLimit": "0x6691b7",
                "blockNumber": "0x5",
                "blockTime": "0x62bd7444",
                "gasLimit": "0x6691b7",
                "gasPrice": "0x9184e72a000",
                "input": "0x9507d39abeced09521047d05b8960b7e7bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2",
                "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                "value": "0x0",
            }
        ],
    ],
]


@pytest.mark.parametrize(
    "lessons, seed_seqs",
    [
        (
            [{"description": "my lesson 1", "transactions": suggested_seed_seqs[0]}],
            suggested_seed_seqs[0],
        ),
        (
            [
                {"description": "my lesson 1", "transactions": suggested_seed_seqs[0]},
                {"description": "my lesson 2", "transactions": suggested_seed_seqs[1]},
            ],
            suggested_seed_seqs[0] + suggested_seed_seqs[1],
        ),
    ],
)
def test_fuzz_run_fuzzing_lessons(
    api_key, tmp_path, hardhat_fuzzing_lessons_project, lessons, seed_seqs
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets=["contracts/LessonTestContract.sol"],
        deployed_contract_address="0xc2E17c0b175402d669Baa4DBDF3C5Ea3CF010cAC",
    )

    with open(".fuzzing_lessons.json", "w") as f:
        json.dump({"lessons": lessons}, f)

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
        "address-under-test": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
        "other-addresses-under-test": None,
        "steps": [
            {
                "blockCoinbase": "0x0000000000000000000000000000000000000000",
                "blockDifficulty": "0x0",
                "blockGasLimit": "0x6691b7",
                "blockTimestamp": "0x62bd726f",
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
        "suggested-seed-seqs": seed_seqs,
    }


@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("hardhat_project"),
        lazy_fixture("truffle_project"),
        lazy_fixture("brownie_project"),
        lazy_fixture("dapptools_project"),
        lazy_fixture("foundry_project"),
    ],
)
@pytest.mark.parametrize("absolute_targets", [True, False])
@pytest.mark.parametrize("absolute_build_dir", [True, False])
@pytest.mark.parametrize("absolute_sources_dir", [True, False])
@pytest.mark.parametrize("folder_target", [True, False])
def test_fuzz(
    api_key,
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
    assert_is_equal(payload["contracts"], processed_payload["contracts"])
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"


@pytest.mark.parametrize(
    "ide",
    [
        lazy_fixture("hardhat_project"),
        lazy_fixture("truffle_project"),
        lazy_fixture("brownie_project"),
        lazy_fixture("dapptools_project"),
        lazy_fixture("foundry_project"),
    ],
)
def test_fuzz_empty_artifacts(api_key, tmp_path, ide: Dict[str, any]):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**ide, "build_directory": "wrong_directory"},
    )
    os.makedirs(tmp_path.joinpath("wrong_directory"))
    if ide["ide"] == "foundry" or ide["ide"] == "hardhat":
        build_info = tmp_path.joinpath("wrong_directory", "build-info")
        os.makedirs(build_info)
        with open(build_info.joinpath("test.json"), "w") as f:
            f.write(
                '{"input": {"sources": {}}, "output": {"sources": {}, "contracts": {}}}'
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
        result = runner.invoke(cli, ["run", "--no-prompts"])

    assert result.exit_code == 2
    assert (
        f"Error: No contract being submitted. "
        f"Please check your config (hint: build_directory path or targets paths) or recompile contracts\n"
        in result.output
    )

    start_faas_campaign_mock.assert_not_called()


@pytest.mark.parametrize("ide", [lazy_fixture("hardhat_project")])
@pytest.mark.parametrize(
    "corpus_target, time_limit, project, chain_id, enable_cheat_codes, string_chain_id",
    [
        (None, None, None, None, None, True),
        (
            "cmp_9e931b147e7143a8b53041c708d5474e",
            "15mins",
            "Test Project 1",
            "0x2a",
            True,
            True,
        ),
        (None, None, None, "0x11", False, False),
        (None, None, None, "0x22", None, False),
        (None, None, None, 42, None, False),
        (None, None, None, "", None, True),
    ],
)
def test_fuzz_parameters(
    api_key,
    tmp_path,
    ide: Dict[str, any],
    corpus_target: Optional[str],
    time_limit: Optional[str],
    project: Optional[str],
    chain_id: Optional[Union[str, int]],
    enable_cheat_codes: Optional[bool],
    string_chain_id: bool,
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **ide,
        time_limit=time_limit,
        project=project,
        chain_id=chain_id,
        enable_cheat_codes=enable_cheat_codes,
        string_chain_id=string_chain_id,
    )

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
    assert payload.get("timeLimit", None) == (900 if time_limit else None)
    assert payload.get("project", None) == project or None

    _chain_id = chain_id
    if type(_chain_id) == int:
        _chain_id = hex(_chain_id)

    assert payload["parameters"].get("chain-id") == (_chain_id or None)
    assert payload["parameters"].get("enable-cheat-codes") == (
        None if enable_cheat_codes is None else enable_cheat_codes
    )


def test_rpc_not_running(api_key, tmp_path):
    write_config(base_path=str(tmp_path))

    with patch.object(requests, "request") as mocker:
        mocker.side_effect = RequestException()

        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert (
        "HTTP error calling RPC method eth_getBlockByNumber with parameters"
        in result.output
    )
    assert result.exit_code != 0


def test_fuzz_no_deployed_address(api_key, tmp_path):
    runner = CliRunner()
    write_config(not_include=["deployed_contract_address"])

    result = runner.invoke(cli, ["run", "contracts", "--no-prompts"])
    assert (
        "Error: Invalid config: Deployed contract address not provided.\n"
        in result.output
    )
    assert result.exit_code != 0


def test_fuzz_no_target(api_key, tmp_path):
    runner = CliRunner()
    write_config(not_include=["targets"])

    result = runner.invoke(cli, ["run", "--no-prompts"])
    assert "Error: Invalid config: Targets not provided.\n" in result.output
    assert result.exit_code != 0


@pytest.mark.parametrize(
    "status_code, text, _json, exc, error_output",
    [
        (500, "Internal Server Error", None, None, "<JSONDecodeError>"),
        (
            403,
            None,
            {"detail": "No subscription", "error": "SubscriptionError"},
            None,
            "Error: BadStatusCode: Subscription Error\nDetail: No subscription\n",
        ),
        (
            403,
            None,
            {
                "detail": "Monthly fuzzing limit is reached. Review your limits in the dashboard at https://fuzzing.diligence.tools/",
                "error": "FuzzingLimitReachedError",
            },
            None,
            "Error: BadStatusCode: Fuzzing Limit Reached Error\nDetail: Monthly fuzzing limit is reached. Review your limits in the dashboard at https://fuzzing.diligence.tools/\n",
        ),
        (
            403,
            None,
            {"detail": "Access denied", "error": "AccessDenied"},
            None,
            "Error: BadStatusCode: Got http status code 403 for request https://fuzzing-test.diligence.tools/api/"
            "campaigns/?start_immediately=true\nDetail: Access denied\n",
        ),
        (
            500,
            None,
            {"detail": "Server error", "error": "InternalServerError"},
            None,
            "Error: BadStatusCode: Got http status code 500 for request https://fuzzing-test.diligence.tools/api/"
            "campaigns/?start_immediately=true\nDetail: Server error\n",
        ),
        (
            500,
            None,
            None,
            RequestException(),
            "Error: RequestError: Error starting FaaS campaign\nDetail: RequestException()\n",
        ),
    ],
)
def test_fuzz_submission_error(
    api_key,
    tmp_path,
    brownie_project,
    status_code: int,
    text: Optional[str],
    _json: Optional[Mapping[str, any]],
    exc: Optional[Exception],
    error_output: str,
):
    if error_output == "<JSONDecodeError>":
        error_output = (
            "Error: RequestError: Error starting FaaS campaign\n"
            "Detail: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')\n"
        )
        _platform, py_version = get_python_version()
        if _platform == "CPython" and py_version == "3.6":
            error_output = (
                "Error: RequestError: Error starting FaaS campaign\n"
                "Detail: JSONDecodeError('Expecting value: line 1 column 1 (char 0)',)\n"
            )
        elif _platform == "PyPy":
            error_output = (
                "Error: RequestError: Error starting FaaS campaign\n"
                "Detail: JSONDecodeError('Error when decoding Infinity: line 1 column 2 (char 1)')\n"
            )
            if py_version == "3.6":
                error_output = (
                    "Error: RequestError: Error starting FaaS campaign\n"
                    "Detail: JSONDecodeError('Error when decoding Infinity: line 1 column 2 (char 1)',)\n"
                )

    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **brownie_project,
        faas_url="https://fuzzing-test.diligence.tools/",
    )

    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in get_test_case(
            "testdata/brownie_project/contracts.json"
        ).values()
    }

    with mocked_rpc_client(
        get_test_case("testdata/brownie_project/blocks.json"), codes
    ), patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors"
    ), requests_mock.Mocker() as m:
        m.register_uri(
            "POST", "http://localhost:9898", real_http=True
        )  # will be passed to mocker from the `mocked_rpc_client`
        m.register_uri(
            "POST",
            "https://example-us.com/oauth/token",
            json={"access_token": "test-token"},
        )
        if exc:
            m.register_uri(
                "POST",
                "https://fuzzing-test.diligence.tools/api/campaigns/?start_immediately=true",
                exc=exc,
            )
        else:
            m.register_uri(
                "POST",
                "https://fuzzing-test.diligence.tools/api/campaigns/?start_immediately=true",
                status_code=status_code,
                text=text,
                json=_json,
            )
        runner = CliRunner()
        cmd = ["run"]
        result = runner.invoke(cli, cmd)

    assert result.exit_code == 1
    assert result.output == error_output


@pytest.mark.parametrize("scribble_meta", [True, False, "exc"])
def test_fuzz_add_scribble_meta(
    api_key, tmp_path, hardhat_project, scribble_meta: Union[bool, str]
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **hardhat_project
    )
    if scribble_meta is True:
        with open(f"{tmp_path}/{SCRIBBLE_ARMING_META_FILE}", "w") as f:
            json.dump({"some_property": "some_value"}, f)

    if scribble_meta == "exc":
        with open(f"{tmp_path}/{SCRIBBLE_ARMING_META_FILE}", "w") as f:
            f.write("wrong_json")

    blocks = get_test_case("testdata/hardhat_project/blocks.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in get_test_case(
            "testdata/hardhat_project/contracts.json"
        ).values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors"
    ):
        campaign_id = "cmp_517b504e67474ab6b26a92a58e0adbf9"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        cmd = ["run"]
        result = runner.invoke(cli, cmd)

    if type(scribble_meta) == bool:
        start_faas_campaign_mock.assert_called_once()
        payload = start_faas_campaign_mock.call_args[0][0]
        assert result.exit_code == 0
        assert (
            f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
            in result.output
        )
        assert payload.get("instrumentationMetadata", None) == (
            {"some_property": "some_value"} if scribble_meta else None
        )
    else:
        start_faas_campaign_mock.assert_not_called()
        assert result.exit_code == 1

        output = (
            "Error: ScribbleMetaError: Error getting Scribble arming metadata\n"
            "Detail: JSONDecodeError('Expecting value: line 1 column 1 (char 0)')\n"
        )
        _platform, py_version = get_python_version()
        if _platform == "CPython" and py_version == "3.6":
            output = (
                "Error: ScribbleMetaError: Error getting Scribble arming metadata\n"
                "Detail: JSONDecodeError('Expecting value: line 1 column 1 (char 0)',)\n"
            )
        elif _platform == "PyPy":
            output = (
                "Error: ScribbleMetaError: Error getting Scribble arming metadata\n"
                "Detail: JSONDecodeError(\"Unexpected 'w': line 1 column 1 (char 0)\")\n"
            )
            if py_version == "3.6":
                output = (
                    "Error: ScribbleMetaError: Error getting Scribble arming metadata\n"
                    "Detail: JSONDecodeError(\"Unexpected 'w': line 1 column 1 (char 0)\",)\n"
                )

        assert result.output == output

    # cleanup
    del os.environ["FUZZ_CONFIG_FILE"]
