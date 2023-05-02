from typing import Dict
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pytest_lazyfixture import lazy_fixture

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide import TruffleArtifacts
from tests.common import assert_is_equal, get_test_case, mocked_rpc_client
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
    tmp_path,
    ide: Dict[str, any],
    monkeypatch,
):
    monkeypatch.setenv(
        "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    )
    monkeypatch.setenv("FUZZ_RPC_URL", "http://localhost:9898")
    monkeypatch.setenv("FUZZ_FAAS_URL", "http://localhost:9899")

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
