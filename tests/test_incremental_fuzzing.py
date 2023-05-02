from typing import Optional
from unittest.mock import Mock, patch

from click.testing import CliRunner
from pytest import mark

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc.rpc import RPCClient
from tests.common import get_test_case, write_config


@mark.parametrize(
    "project, incremental, corpus_target, error_detail",
    [
        (
            None,
            True,
            None,
            "Invalid config: `incremental` config parameter is set to true without specifying `project`.",
        ),
        (
            "test-project-1",
            True,
            "cmp_123",
            "Invalid config: Both `incremental` and `corpus_target` are set. "
            "Please set only one option.",
        ),
    ],
)
def test_parameters_check(
    api_key,
    tmp_path,
    project: Optional[str],
    incremental: Optional[bool],
    corpus_target: Optional[str],
    error_detail: str,
):
    write_config(
        base_path=str(tmp_path),
        project=project,
        incremental=incremental,
        corpus_target=corpus_target,
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["run", f"{tmp_path}/contracts", "--no-prompts"])

    assert result.exit_code == 2
    assert (
        f"Usage: cli run [OPTIONS] [TARGETS]...\nTry 'cli run --help' for help.\n\nError: {error_detail}\n"
        == result.output
    )


@mark.parametrize(
    "project, incremental, corpus_target, corpus_target_result",
    [
        (
            "test-project-1",
            None,
            "cmp_7fff6281fbea4677a92ebd1f42cdc501",
            "cmp_7fff6281fbea4677a92ebd1f42cdc501",
        ),
        ("test-project-1", None, "Test Campaign 1", "Test Campaign 1"),
        (
            "test-project-1",
            False,
            "cmp_93fa97a6aadf4331ae852de761055454",
            "cmp_93fa97a6aadf4331ae852de761055454",
        ),
        ("test-project-1", False, "Test Campaign 2", "Test Campaign 2"),
        ("test-project-1", True, None, "test-project-1"),
        (
            "prj_babfbadc53574442aa062911947d13fa",
            True,
            None,
            "prj_babfbadc53574442aa062911947d13fa",
        ),
    ],
)
def test_incremental_fuzzing(
    api_key,
    tmp_path,
    project: Optional[str],
    incremental: Optional[bool],
    corpus_target: Optional[str],
    corpus_target_result: str,
    brownie_project,
):
    write_config(
        ide="brownie",
        base_path=str(tmp_path),
        project=project,
        incremental=incremental,
        corpus_target=corpus_target,
    )

    with patch.object(RPCClient, "get_code", Mock(return_value="0x1")), patch.object(
        RPCClient,
        "get_all_blocks",
        Mock(return_value=get_test_case("testdata/ganache-all-blocks.json")),
    ), patch(
        "fuzzing_cli.fuzz.run.handle_validation_errors", new=Mock(return_value=[])
    ), patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        start_faas_campaign_mock.return_value = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        runner = CliRunner()
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts", "--no-prompts"])

    assert result.exit_code == 0
    assert (
        f"You can view campaign here: http://localhost:9899/campaigns/560ba03a-8744-4da6-aeaa-a62568ccbf44"
        in result.output
    )
    start_faas_campaign_mock.assert_called_once()
    request_payload = start_faas_campaign_mock.call_args[0][0]
    assert request_payload["corpus"].get("target") == corpus_target_result
