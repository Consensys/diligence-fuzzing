import json
from unittest.mock import patch

import pytest
import requests_mock
from click.testing import CliRunner
from requests import RequestException

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc import RPCClient
from tests.common import write_config


def test_get_corpus(tmp_path, hardhat_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        contract_exists_mock.return_value = True
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
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-a",
                "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
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
            "address-under-test": "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
            "steps": [{"hash": "0xtest"}],
            "other-addresses-under-test": None,
        },
        "sources": {},
        "contracts": [],
        "project": None,
    }


def test_transactions_limit(tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m, patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock:
        contract_exists_mock.return_value = True
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
        RPCClient, "contract_exists"
    ) as contract_exists_mock:
        contract_exists_mock.return_value = True
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
        f'HTTP error calling RPC method eth_getBlockByNumber with parameters: ["latest", true]'
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
        RPCClient, "contract_exists"
    ) as contract_exists_mock:
        contract_exists_mock.return_value = True
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


def test_address_not_found(tmp_path):
    write_config(
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/MasterChefV2.sol",
    )

    with requests_mock.Mocker() as m:
        m.register_uri(
            "POST",
            "http://localhost:9898",
            [
                {"status_code": 200, "json": {"result": None}},
                {"status_code": 200, "json": {"result": "0x0a123"}},
                {"status_code": 200, "json": {"result": "0x"}},
            ],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts/MasterChefV2.sol",
                "-a",
                "0xa7f2264164B49C866857f34aC4d7371c8e85e435",
                "-m",
                "0xD89F8B7eA865EF67b32Fc661c800819660324Bc9,0x4614F99875763Cd84656Ec658eb38E841cE8B172",
            ],
        )

    assert result.exit_code == 1
    assert (
        f"Unable to find contracts deployed at "
        f"0xa7f2264164B49C866857f34aC4d7371c8e85e435, 0x4614F99875763Cd84656Ec658eb38E841cE8B172"
        in result.output
    )
