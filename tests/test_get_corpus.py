import os
from unittest.mock import Mock, patch

import pytest
import requests_mock
from click.testing import CliRunner
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide.truffle import TruffleArtifacts
from fuzzing_cli.fuzz.rpc.rpc import RPCClient
from tests.common import get_code_mocker, get_test_case, write_config
from tests.testdata.truffle_project.mocks import db_calls_mock


def test_get_corpus(tmp_path, hardhat_project, monkeypatch):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "validate_seed_state"
    ) as validate_seed_state_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        RPCClient, "check_contracts", Mock(return_value=True)
    ):
        validate_seed_state_mock.return_value = ({}, [])
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        m.register_uri(
            "POST",
            "http://localhost:9898",
            status_code=200,
            json={"result": {"number": "0x0", "transactions": [{"hash": "0xtest"}]}},
        )

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
            "address-under-test": "0x81c5D21c4a70ADE85b39689DF5a14B5b5027C28e",
            "steps": [{"hash": "0xtest"}],
            "other-addresses-under-test": None,
        },
        "sources": {},
        "contracts": [],
        "quickCheck": False,
    }


def test_transactions_limit(tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "validate_seed_state"
    ) as validate_seed_state_mock:
        validate_seed_state_mock.return_value = ({}, [])
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


def test_call_error(tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "validate_seed_state"
    ) as validate_seed_state_mock:
        validate_seed_state_mock.return_value = ({}, [])
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
def test_no_latest_block(tmp_path, block):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "validate_seed_state"
    ) as validate_seed_state_mock:
        validate_seed_state_mock.return_value = ({}, [])
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


def test_missing_targets_detection(tmp_path, truffle_project):
    # multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=["contracts/Foo.sol"],
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
    )
    blocks = get_test_case("testdata/truffle_project/blocks.json")
    contracts = get_test_case("testdata/truffle_project/contracts.json")
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

        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 0
    payload = start_faas_campaign_mock.call_args[0][0]
    assert (
        payload["corpus"]["address-under-test"]
        == "0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065"
    )
    assert len(payload["contracts"]) == 1
    assert payload["contracts"][0]["contractName"] == "Foo"
    assert len(list(payload["sources"].keys())) == 4
    # assert list(payload["sources"].keys())[0] == f"{tmp_path}/contracts/Foo.sol"
    assert (
        f"⚠️ Following contracts were not included into the seed state:\n"
        f"  ◦ Address: 0x07d9fb5736cd151c8561798dfbda5dbcf54cb9e6 Source File: {tmp_path}/contracts/Migrations.sol Contract Name: Migrations\n"
        f"  ◦ Address: 0x6a432c13a2e980a78f941c136ec804e7cb67e0d9 Source File: {tmp_path}/contracts/Bar.sol Contract Name: Bar\n"
        f"  ◦ Address: 0x6bcb21de38753e485f7678c7ada2a63f688b8579 Source File: {tmp_path}/contracts/ABC.sol Contract Name: ABC"
        in result.output
    )


@pytest.mark.parametrize("absolute_targets", [True, False])
def test_mismatched_targets_detection(
    tmp_path, truffle_project, absolute_targets: bool
):
    # multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets=["contracts/ABC.sol"],
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
        absolute_targets=absolute_targets,
    )
    blocks = get_test_case("testdata/truffle_project/blocks.json")
    contracts = get_test_case("testdata/truffle_project/contracts.json")
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

        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 1
    assert start_faas_campaign_mock.called is False
    assert (
        f"Error: Following targets were provided without setting up "
        f"their addresses in the config file or as parameters to `fuzz run`:\n  "
        f"◦ Target: {tmp_path}/contracts/ABC.sol "
        f"Address: 0x6bcb21de38753e485f7678c7ada2a63f688b8579\n" == result.output
    )


def test_dangling_targets_detection(tmp_path, truffle_project):
    # multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets="",
        deployed_contract_address="0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
    )
    blocks = get_test_case("testdata/truffle_project/blocks.json")
    contracts = get_test_case("testdata/truffle_project/contracts.json")
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

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
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

    assert result.exit_code == 1
    assert start_faas_campaign_mock.called is False
    assert (
        f"Error: Following contract's addresses were provided without specifying them as "
        f"a target prior to `fuzz run`:\n"
        f"  ◦ Address: 0x6a432c13a2e980a78f941c136ec804e7cb67e0d9 Target: {tmp_path}/contracts/Bar.sol\n"
        == result.output
    )


def test_unknown_addresses_detection(tmp_path, truffle_project):
    # TODO: multiple deployments
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="build",
        targets="contracts/Foo.sol",
        deployed_contract_address="0x0000fB2eb51789aBd1a9f2FE83d69C6f4C8830aa",
    )
    blocks = get_test_case("testdata/truffle_project/blocks.json")
    contracts = get_test_case("testdata/truffle_project/contracts.json")
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

        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", "-m", "0x0000fB2eb51789aBd1a9f2FE83d69C6f4C88bbbb"]
        )

    assert result.exit_code == 1
    assert start_faas_campaign_mock.called is False
    assert (
        "Error: Unable to find contracts deployed at 0x0000fb2eb51789abd1a9f2fe83d69c6f4c8830aa, "
        "0x0000fb2eb51789abd1a9f2fe83d69c6f4c88bbbb\n" == result.output
    )
