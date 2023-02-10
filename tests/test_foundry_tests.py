from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from tests.common import assert_is_equal, get_test_case, write_config

build_command = [
    "forge",
    "build",
    "--build-info",
    "--force",
    "--contracts",
    "A",
    "B",
    "C",
    "--optimize",
    "--evm-version",
    "0.8.1",
]


@pytest.mark.parametrize(
    "build_args, build_cmd",
    [
        (None, ["forge", "build", "--build-info", "--force"]),
        (
            "--build-args=--contracts A B C --optimize --evm-version 0.8.1",
            build_command,
        ),
    ],
)
def test_foundry_tests(
    foundry_tests_project,
    tmp_path,
    foundry_config_mock,
    foundry_build_mock,
    build_args,
    build_cmd,
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
            cmd.append(build_args)
        result = runner.invoke(cli, cmd)

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/{campaign_id}"
        in result.output
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
    assert payload["corpus"] == processed_payload["corpus"]
    assert_is_equal(payload["contracts"], processed_payload["contracts"])
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"
