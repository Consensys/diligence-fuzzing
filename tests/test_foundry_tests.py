from typing import Any, Callable, Dict, List, Optional
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from tests.common import assert_is_equal, get_test_case, write_config

empty_build_command = ["forge", "build", "--build-info", "--force"]

build_command = empty_build_command + [
    "--contracts",
    "A",
    "B",
    "C",
    "--optimize",
    "--evm-version",
    "0.8.1",
]


def filter_keys(d: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k in keys}


@pytest.mark.parametrize(
    "build_args, build_cmd, list_args, corpus, contracts, sources",
    [
        (
            None,
            ["forge", "build", "--build-info", "--force"],
            ["--match-path", "test/*"],
            lambda p: p["corpus"],
            lambda p: p["contracts"],
            lambda p: p["sources"],
        ),
        (
            ["--build-args=--contracts A B C --optimize --evm-version 0.8.1"],
            build_command,
            ["--match-path", "test/*"],
            lambda p: p["corpus"],
            lambda p: p["contracts"],
            lambda p: p["sources"],
        ),
        (
            ["--match-path", '"test/Counter*"'],
            empty_build_command,
            ["--match-path", '"test/Counter*"'],
            lambda p: {**p["corpus"], "steps": [p["corpus"]["steps"][0]]},
            lambda p: [p["contracts"][0]],
            lambda p: filter_keys(
                p["sources"],
                ["lib/forge-std/lib/ds-test/src/test.sol", "test/Counter.t.sol"],
            ),
        ),
        (
            ["--match-path", '"test/Counter*"', "--match-contract", '"Counter*"'],
            empty_build_command,
            ["--match-path", '"test/Counter*"', "--match-contract", '"Counter*"'],
            lambda p: {**p["corpus"], "steps": [p["corpus"]["steps"][0]]},
            lambda p: [p["contracts"][0]],
            lambda p: filter_keys(
                p["sources"],
                ["lib/forge-std/lib/ds-test/src/test.sol", "test/Counter.t.sol"],
            ),
        ),
        (
            ["--match-path", "test/Counter*", "--match-contract", "Counter*"],
            empty_build_command,
            ["--match-path", "test/Counter*", "--match-contract", "Counter*"],
            lambda p: {**p["corpus"], "steps": [p["corpus"]["steps"][0]]},
            lambda p: [p["contracts"][0]],
            lambda p: filter_keys(
                p["sources"],
                ["lib/forge-std/lib/ds-test/src/test.sol", "test/Counter.t.sol"],
            ),
        ),
        (
            ["--match-contract", '"Counter*"'],
            empty_build_command,
            ["--match-contract", '"Counter*"'],
            lambda p: {**p["corpus"], "steps": [p["corpus"]["steps"][0]]},
            lambda p: [p["contracts"][0]],
            lambda p: filter_keys(
                p["sources"],
                ["lib/forge-std/lib/ds-test/src/test.sol", "test/Counter.t.sol"],
            ),
        ),
    ],
)
def test_foundry_tests(
    foundry_tests_project,
    tmp_path,
    foundry_config_mock,
    foundry_build_mock,
    foundry_test_list_mock,
    build_args: Optional[List[str]],
    build_cmd: List[str],
    list_args: List[str],
    corpus: Callable[[Dict[str, Any]], Dict[str, Any]],
    contracts: Callable[[Dict[str, Any]], Dict[str, Any]],
    sources: Callable[[Dict[str, Any]], Dict[str, Any]],
):
    write_config(config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path))

    with patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        cmd = [
            "forge",
            "test",
            "--key",
            "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
        ]
        if build_args:
            cmd += build_args
        result = runner.invoke(cli, cmd)

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
        in result.output
    )

    assert (
        foundry_test_list_mock.call_count(
            ["forge", "test", "--list", "--json"] + list_args
        )
        == 1
    )
    assert foundry_config_mock.call_count(["forge", "config"]) == 1
    assert foundry_build_mock.calls[0] == build_cmd
    assert foundry_build_mock.call_count(build_cmd) == 1

    start_faas_campaign_mock.assert_called_once()
    payload = start_faas_campaign_mock.call_args[0][0]

    processed_payload = get_test_case(
        "testdata/foundry_tests_project/processed_payload.json"
    )

    assert payload["parameters"] == processed_payload["parameters"]
    assert payload["corpus"] == corpus(processed_payload)
    assert_is_equal(payload["contracts"], contracts(processed_payload))
    assert payload["sources"] == sources(processed_payload)
    assert payload["name"] == "test-campaign-1"

    foundry_tests_list = {
        "test/Counter.t.sol": {
            "CounterTest": ["testIncrement", "testSetNumber"],
        },
        "test/VulnerableToken.t.sol": {
            "VulnerableTokenTest": ["testTransfer"],
        },
    }
    if list_args != ["--match-path", "test/*"]:
        foundry_tests_list = {
            "test/Counter.t.sol": {
                "CounterTest": ["testIncrement", "testSetNumber"],
            },
        }

    assert payload["foundryTestsList"] == foundry_tests_list
