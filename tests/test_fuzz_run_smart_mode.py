import json
from typing import Dict
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide import TruffleArtifacts
from tests.common import (
    assert_is_equal,
    construct_output,
    get_test_case,
    mocked_rpc_client,
)
from tests.testdata.truffle_project.mocks import db_calls_mock


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
def test_fuzz_run(
    api_key,
    tmp_path,
    ide: Dict[str, any],
    monkeypatch,
):
    monkeypatch.setenv("FUZZ_RPC_URL", "http://localhost:9898")
    monkeypatch.setenv("FUZZ_FAAS_URL", "http://localhost:9899")
    monkeypatch.setenv("FUZZ_SMART_MODE", "true")

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
@pytest.mark.parametrize("provide_targets", [True, False])
@pytest.mark.parametrize("provide_addresses", [True, False])
def test_fuzz_run_with_auto_fixes(
    api_key,
    tmp_path,
    ide: Dict[str, any],
    monkeypatch,
    provide_targets: bool,
    provide_addresses: bool,
):
    monkeypatch.setenv("FUZZ_RPC_URL", "http://localhost:9898")
    monkeypatch.setenv("FUZZ_FAAS_URL", "http://localhost:9899")
    monkeypatch.setenv("FUZZ_BUILD_DIRECTORY", ide["build_directory"])
    monkeypatch.setenv("FUZZ_SOURCES_DIRECTORY", ide["sources_directory"])
    if provide_targets:
        monkeypatch.setenv("FUZZ_TARGETS", json.dumps(ide["targets"]))
    if provide_addresses:
        monkeypatch.setenv(
            "FUZZ_DEPLOYED_CONTRACT_ADDRESS", ide["deployed_contract_address"]
        )
        monkeypatch.setenv(
            "FUZZ_ADDITIONAL_CONTRACTS_ADDRESSES",
            json.dumps(ide["additional_addresses"]),
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
        if not provide_targets or not provide_addresses:
            # there will be a prompt to confirm the fixes
            result = runner.invoke(cli, ["run"], input="y\n")
        else:
            result = runner.invoke(cli, ["run"])

    if not provide_targets and not provide_addresses:
        assert result.exit_code == 2
        assert (
            "Usage: cli run [OPTIONS] [TARGETS]...\n"
            "Try 'cli run --help' for help.\n"
            "\n"
            "Error: Invalid config: No targets specified. Please specify "
            "at least one target (deployed contract address or targets).\n"
            == result.output
        )
        return

    message = ""
    prompt = ""

    if not provide_targets and provide_addresses:
        data = []
        for address in [ide["deployed_contract_address"], *ide["additional_addresses"]]:
            for contract in contracts.values():
                if contract["address"] == address:
                    data.append(
                        f"  ◦ Address: {address.lower()}"
                        f" Target: {tmp_path}/{contract['contractPath']}"
                    )
                    break
        data = "\n".join(data)
        message = (
            "Following contract's addresses were provided as addresses under test without specifying "
            f"them as a target prior to `fuzz run`:\n{data}"
        )
        prompt = "Add them to targets"
    elif provide_targets and not provide_addresses:
        data = []
        for target in ide["targets"]:
            for contract_name, contract in contracts.items():
                if contract["contractPath"] == target:
                    data.append(
                        f"  ◦ Address: {contract['address'].lower()}"
                        f" Source File: {tmp_path}/{contract['contractPath']}"
                        f" Contract Name: {contract_name}"
                    )
                    break
        data = "\n".join(data)
        message = (
            "The following targets were provided without providing addresses of "
            f"respective contracts as addresses under test:\n{data}"
        )
        prompt = "Add them to addresses under test"

    expected_output = construct_output(
        message,
        prompt,
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}",
    )

    assert result.exit_code == 0
    assert expected_output == result.output

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

    expected_addresses_under_test = [
        processed_payload["corpus"]["address-under-test"],
        *processed_payload["corpus"]["other-addresses-under-test"],
    ]
    actual_addresses_under_test = [
        payload["corpus"]["address-under-test"],
        *payload["corpus"]["other-addresses-under-test"],
    ]

    actual_corpus = {
        k: v
        for k, v in payload["corpus"].items()
        if k not in ["address-under-test", "other-addresses-under-test"]
    }
    expected_corpus = {
        k: v
        for k, v in processed_payload["corpus"].items()
        if k not in ["address-under-test", "other-addresses-under-test"]
    }

    assert payload["parameters"] == processed_payload["parameters"]
    # we do it this way because the order of addresses is not guaranteed
    assert_is_equal(expected_addresses_under_test, actual_addresses_under_test)
    assert expected_corpus == actual_corpus
    assert_is_equal(payload["contracts"], processed_payload["contracts"])
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"
