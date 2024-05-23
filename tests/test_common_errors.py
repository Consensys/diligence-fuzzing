import json
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from tests.common import get_test_case, mocked_rpc_client, write_config


@pytest.mark.parametrize(
    "ide,unlinked_contracts",
    [
        (
            lazy_fixture("hardhat_project_with_unlinked_libraries"),
            [
                ("TestLib", "contracts/TestLib.sol", "Bar", "contracts/Bar.sol"),
                ("TestLib", "contracts/TestLib.sol", "Foo", "contracts/Foo.sol"),
            ],
        ),
        (
            lazy_fixture("foundry_project_with_unlinked_libraries"),
            [
                ("TestLib", "src/lib/TestLib.sol", "ABC", "src/ABC.sol"),
                ("TestLib", "src/lib/TestLib.sol", "Bar", "src/Bar.sol"),
            ],
        ),
    ],
)
def test_unlinked_libraries(api_key, tmp_path, ide, unlinked_contracts):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **ide,
    )
    blocks = get_test_case(
        f"testdata/{ide['ide']}_project_with_unlinked_libraries/blocks.json"
    )
    contracts = get_test_case(
        f"testdata/{ide['ide']}_project_with_unlinked_libraries/contracts.json"
    )
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    details = "\n".join(
        [
            f'  ◦ Contract: "{contract_name}" Contract path: "{contract_path}" '
            f'Library: "{lib}" Library path: "{lib_path}"'
            for lib, lib_path, contract_name, contract_path in unlinked_contracts
        ]
    )

    assert result.exit_code == 1
    assert (
        f"Error: Following contracts have unlinked libraries:\n{details}\n"
        f"For more info on library linking please visit "
        f"https://docs.soliditylang.org/en/latest/using-the-compiler.html#library-linking\n"
        == result.output
    )


@pytest.mark.parametrize(
    "ide,build_info_path,unlinked_contracts",
    [
        (
            lazy_fixture("hardhat_project_with_unlinked_libraries"),
            "artifacts/build-info/231cb8d74cc32d8d28f8278fd2bd34a6.json",
            [
                ("154d8911a162d9fe8513835584d2c10b72", "Bar", "contracts/Bar.sol"),
                ("154d8911a162d9fe8513835584d2c10b72", "Foo", "contracts/Foo.sol"),
            ],
        ),
        (
            lazy_fixture("foundry_project_with_unlinked_libraries"),
            "out/build-info/e9a554f23646e3a59be290d9d1a021fb.json",
            [
                ("a6697e97c84a48a247184558696f600b66", "ABC", "src/ABC.sol"),
                ("a6697e97c84a48a247184558696f600b66", "Bar", "src/Bar.sol"),
            ],
        ),
    ],
)
def test_unlinked_libraries_detection_fallback(
    api_key, tmp_path, ide, build_info_path, unlinked_contracts
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **ide,
    )

    # here we purposefully remove the linkReferences from the build-info file
    # to force the fallback detection of unlinked libraries
    with open(f"{tmp_path}/{build_info_path}", "r") as f:
        build_info = json.load(f)
        for p in build_info["output"]["contracts"].keys():
            for contract_name in build_info["output"]["contracts"][p].keys():
                build_info["output"]["contracts"][p][contract_name]["evm"]["bytecode"][
                    "linkReferences"
                ] = {}
                build_info["output"]["contracts"][p][contract_name]["evm"][
                    "deployedBytecode"
                ]["linkReferences"] = {}
    with open(f"{tmp_path}/{build_info_path}", "w") as f:
        json.dump(build_info, f)

    blocks = get_test_case(
        f"testdata/{ide['ide']}_project_with_unlinked_libraries/blocks.json"
    )
    contracts = get_test_case(
        f"testdata/{ide['ide']}_project_with_unlinked_libraries/contracts.json"
    )
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    details = "\n".join(
        [
            f"  ◦ Contract: {contract_name} Contract path: {contract_path} Library hash: {lib_hash}"
            for lib_hash, contract_name, contract_path in unlinked_contracts
        ]
    )

    assert result.exit_code == 1
    assert (
        f"Error: Following contracts have unlinked libraries:\n{details}\n"
        f"Fuzzing CLI provides only library hashes because it wasn't able to one's name and path "
        f"from compilation artifacts. Please check your IDE settings to enable full solc compiler output.\n"
        f"For more info on library linking please visit "
        f"https://docs.soliditylang.org/en/latest/using-the-compiler.html#library-linking\n"
        == result.output
    )
