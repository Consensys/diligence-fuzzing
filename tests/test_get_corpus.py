import os
from unittest.mock import patch

import pytest
import requests_mock
from click.testing import CliRunner
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide.truffle import TruffleArtifacts
from fuzzing_cli.fuzz.rpc.rpc import RPCClient
from tests.common import (
    construct_output,
    get_code_mocker,
    get_test_case,
    mocked_rpc_client,
    write_config,
)
from tests.testdata.truffle_project.mocks import db_calls_mock

TESTS_PARAMETRIZATION = (
    "with_prompt, auto_fix",
    [
        (True, True),
        (True, False),
        (False, False),
    ],
)


def truffle_mocked_context_invoke(
    tmp_path, with_prompt, auto_fix, blocks=None, contracts=None, cmd=None
):
    blocks = blocks or get_test_case("testdata/truffle_project/blocks.json")
    contracts = contracts or get_test_case("testdata/truffle_project/contracts.json")
    query_truffle_db_mocker = db_calls_mock(contracts, str(tmp_path))
    os.chdir(tmp_path)
    with patch.object(RPCClient, "get_all_blocks") as get_all_blocks_mock, patch.object(
        RPCClient, "get_code"
    ) as get_code_mock, patch.object(
        TruffleArtifacts, "query_truffle_db"
    ) as query_truffle_db_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = blocks
        get_code_mock.side_effect = get_code_mocker(contracts)
        query_truffle_db_mock.side_effect = query_truffle_db_mocker
        start_faas_campaign_mock.return_value = "cmp_0"
        cmd = cmd or ["run"]
        if not with_prompt:
            cmd.append("--no-prompts")
        runner = CliRunner()
        result = runner.invoke(cli, cmd, input="y\n" if auto_fix else "n\n")
        return result, start_faas_campaign_mock


def test_get_corpus(api_key, tmp_path, hardhat_project, monkeypatch):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    mocked_block = {
        "number": "0x0",
        "miner": "0x0",
        "difficulty": "0x0",
        "gasLimit": "0x0",
        "timestamp": "0x0",
        "transactions": [{"hash": "0xtest", "to": "0x0"}],
    }

    with mocked_rpc_client([mocked_block], {}), patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors",
    ), patch.object(FaasClient, "start_faas_campaign") as start_faas_campaign_mock:
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/Foo.sol",
                "-a",
                "0x81c5D21c4a70ADE85b39689DF5a14B5b5027C28e",
            ],
        )

    assert result.exit_code == 0

    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        "You can view campaign here: http://localhost:9899/campaigns/560ba03a-8744-4da6-aeaa-a62568ccbf44"
        in result.output
    )

    request_payload = {
        **called_with[0][0],
        "sources": {},
        "contracts": [],
        "name": "test",
    }
    assert request_payload == {
        "parameters": {
            "discovery-probability-threshold": 0.0,
            "num-cores": 1,
            "assertion-checking-mode": 1,
        },
        "name": "test",
        "corpus": {
            "address-under-test": "0x81c5d21c4a70ade85b39689df5a14b5b5027c28e",
            "steps": [
                {
                    "hash": "0xtest",
                    "blockCoinbase": "0x0",
                    "blockDifficulty": "0x0",
                    "blockGasLimit": "0x0",
                    "blockTimestamp": "0x0",
                    "to": "0x0",
                }
            ],
            "other-addresses-under-test": None,
        },
        "sources": {},
        "contracts": [],
        "quickCheck": False,
        "mapToOriginalSource": False,
    }


def test_transactions_limit(api_key, tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors",
    ):
        m.register_uri(
            "POST",
            "http://localhost:9898",
            status_code=200,
            json={"result": {"number": "0x270f"}},  # 0x270f = 9999
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-a",
                "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
            ],
        )

    assert result.exit_code == 1
    assert (
        "Number of blocks existing on the ethereum node running at http://localhost:9898 can not exceed 10000. "
        "Did you pass the correct RPC url?" in result.output
    )


def test_call_error(api_key, tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors",
    ):
        m.register_uri("POST", "http://localhost:9898", exc=RequestException)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-a",
                "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
            ],
        )

    assert result.exit_code == 1
    assert (
        f"HTTP error calling RPC method eth_getBlockByNumber with parameters: ['latest', True]"
        f"\nAre you sure the RPC is running at http://localhost:9898?" in result.output
    )


@pytest.mark.parametrize("block", [None, {"number": "0x1", "transactions": []}])
def test_no_latest_block(api_key, tmp_path, block, foundry_project):
    write_config(**{**foundry_project, "build_directory": f"{tmp_path}/out"})

    with requests_mock.Mocker() as m, patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors",
    ):
        m.register_uri(
            "POST", "http://localhost:9898", status_code=200, json={"result": block}
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-a",
                "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
            ],
        )

    assert result.exit_code == 2
    assert (
        f"No transactions were found in an ethereum node running at http://localhost:9898"
        in result.output
    )


@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_not_targeted_contracts(
    api_key,
    tmp_path,
    truffle_project,
    with_prompt: bool,
    auto_fix: bool,
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=["contracts/Foo.sol"],
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
    )
    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path, with_prompt, auto_fix
    )

    assert result.exit_code == 0
    payload = start_faas_campaign_mock.call_args[0][0]
    assert (
        payload["corpus"]["address-under-test"]
        == "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065"
    )
    if with_prompt and auto_fix:
        assert len(payload["contracts"]) == 4
    else:
        assert len(payload["contracts"]) == 1

    output = (
        f"⚠️ Following contracts were not included into the seed state:\n"
        f"  ◦ Address: 0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6 Source File: {tmp_path}/contracts/Migrations.sol Contract Name: Migrations\n"
        f"  ◦ Address: 0x6a432c13a2e980a78f941c136ec804e7cb67e0d9 Source File: {tmp_path}/contracts/Bar.sol Contract Name: Bar\n"
        f"  ◦ Address: 0x6bcb21de38753e485f7678c7ada2a63f688b8579 Source File: {tmp_path}/contracts/ABC.sol Contract Name: ABC"
    )
    prompt = "Add them to targets"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"
    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
        )
        == result.output
    )


@pytest.mark.parametrize("absolute_targets", [True, False])
@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_contract_target_not_set(
    api_key,
    tmp_path,
    truffle_project,
    absolute_targets: bool,
    with_prompt: bool,
    auto_fix: bool,
):
    # multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=truffle_project["targets"],
        deployed_contract_address="0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6",
        additional_addresses=[
            "0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
        ],
        absolute_targets=absolute_targets,
    )
    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path, with_prompt, auto_fix
    )

    output = (
        "The following targets were provided without providing addresses of "
        f"respective contracts as addresses under test:\n"
        f"  ◦ Address: 0x6bcb21de38753e485f7678c7ada2a63f688b8579 "
        f"Source File: {tmp_path}/contracts/ABC.sol Contract Name: ABC"
    )
    prompt = "Add them to addresses under test"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"

    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
            error=True if not auto_fix else False,
        )
        == result.output
    )

    if not with_prompt or not auto_fix:
        assert result.exit_code == 1
        assert start_faas_campaign_mock.called is False
    else:
        assert result.exit_code == 0
        assert start_faas_campaign_mock.called is True
        payload = start_faas_campaign_mock.call_args[0][0]
        assert (
            payload["corpus"]["address-under-test"]
            == "0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6"
        )
        assert payload["corpus"]["other-addresses-under-test"] == [
            "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065",
            "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9",
            "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
        ]


@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_source_target_not_set(
    api_key,
    tmp_path,
    truffle_project,
    with_prompt: bool,
    auto_fix: bool,
):
    # multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets="",
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
    )

    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path,
        with_prompt,
        auto_fix,
        cmd=[
            "run",
            f"{tmp_path}/contracts/Foo.sol",
            f"{tmp_path}/contracts/ABC.sol",
            f"{tmp_path}/contracts/Migrations.sol",
            "-m",
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9, "
            "0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6, "
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
        ],
    )

    output = (
        "Following contract's addresses were provided as addresses under test without specifying "
        f"them as a target prior to `fuzz run`:\n"
        f"  ◦ Address: 0x6a432c13a2e980a78f941c136ec804e7cb67e0d9 Target: {tmp_path}/contracts/Bar.sol"
    )
    prompt = "Add them to targets"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"

    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
            error=True if not auto_fix else False,
        )
        == result.output
    )

    if not with_prompt or not auto_fix:
        assert result.exit_code == 1
        assert start_faas_campaign_mock.called is False
    else:
        assert result.exit_code == 0
        payload = start_faas_campaign_mock.call_args[0][0]
        assert (
            payload["corpus"]["address-under-test"]
            == "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065"
        )
        assert payload["corpus"]["other-addresses-under-test"] == [
            "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9",
            "0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6",
            "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
        ]


@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_unknown_contracts(
    api_key,
    tmp_path,
    truffle_project,
    with_prompt: bool,
    auto_fix: bool,
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=truffle_project["targets"],
        deployed_contract_address="0x0000fB2eb51789aBd1a9f2FE83d69C6f4C8830aa",
        additional_addresses=[
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
            "0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6",
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
            "0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
            "0x0000fB2eb51789aBd1a9f2FE83d69C6f4C88bbbb",
        ],
    )
    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path, with_prompt, auto_fix
    )

    output = (
        "Unable to find contracts with following addresses:\n"
        "  ◦ 0x0000fb2eb51789abd1a9f2fe83d69c6f4c8830aa\n"
        "  ◦ 0x0000fb2eb51789abd1a9f2fe83d69c6f4c88bbbb"
    )
    prompt = "Remove ones from addresses under test"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"

    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
            error=True if not auto_fix else False,
        )
        == result.output
    )

    if not with_prompt or not auto_fix:
        assert result.exit_code == 1
        assert start_faas_campaign_mock.called is False
    else:
        assert result.exit_code == 0
        payload = start_faas_campaign_mock.call_args[0][0]
        assert (
            payload["corpus"]["address-under-test"]
            == "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9"
        )
        assert payload["corpus"]["other-addresses-under-test"] == [
            "0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6",
            "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
            "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065",
        ]


@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_not_deployed_contracts(
    api_key,
    tmp_path,
    truffle_project,
    with_prompt: bool,
    auto_fix: bool,
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=truffle_project["targets"],
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
        additional_addresses=[
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
        ],
    )
    # remove Migrations contract from the list
    blocks = [
        block
        for block in get_test_case("testdata/truffle_project/blocks.json")
        if block["number"] != "0x1"
    ]

    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path, with_prompt, auto_fix, blocks=blocks
    )

    output = (
        "⚠️ Following contracts were not deployed to RPC node:\n"
        f"  ◦ Source File: {tmp_path}/contracts/Migrations.sol Contract Name: Migrations"
    )
    prompt = "Remove them from targets"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"

    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
            error=False,
        )
        == result.output
    )

    assert result.exit_code == 0
    payload = start_faas_campaign_mock.call_args[0][0]
    assert (
        payload["corpus"]["address-under-test"]
        == "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065"
    )
    assert payload["corpus"]["other-addresses-under-test"] == [
        "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9",
        "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
    ]


@pytest.mark.parametrize(*TESTS_PARAMETRIZATION)
def test_contracts_with_no_artifact(
    api_key,
    tmp_path,
    truffle_project,
    with_prompt: bool,
    auto_fix: bool,
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=[
            "contracts/Foo.sol",
            "contracts/Bar.sol",
            "contracts/ABC.sol",
        ],
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
        additional_addresses=[
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
            "0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6",
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
        ],
    )
    # leave Migration contract in the blocks, but remove one from the contracts
    contracts = {
        k: v
        for k, v in get_test_case("testdata/truffle_project/contracts.json").items()
        if k != "Migrations"
    }
    result, start_faas_campaign_mock = truffle_mocked_context_invoke(
        tmp_path, with_prompt, auto_fix, contracts=contracts
    )

    output = (
        f"⚠️ No artifact found for following deployed contracts:\n"
        f"  ◦ 0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6\n"
        f"This could be due to disabled metadata hash generation in your compiler settings."
    )
    prompt = "Remove ones from addresses under test"
    cmd_result = "You can view campaign here: http://localhost:9899/campaigns/cmp_0"

    assert (
        construct_output(
            output,
            prompt if with_prompt else None,
            cmd_result,
            "y" if auto_fix else "n",
            error=False,
        )
        == result.output
    )

    assert result.exit_code == 0
    payload = start_faas_campaign_mock.call_args[0][0]
    assert (
        payload["corpus"]["address-under-test"]
        == "0x1672fb2eb51789abd1a9f2fe83d69c6f4c883065"
    )

    addresses = [
        "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9",
        "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
    ]
    if not with_prompt or not auto_fix:
        addresses = [
            "0x6a432c13a2e980a78f941c136ec804e7cb67e0d9",
            "0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6",
            "0x6bcb21de38753e485f7678c7ada2a63f688b8579",
        ]

    assert payload["corpus"]["other-addresses-under-test"] == addresses
