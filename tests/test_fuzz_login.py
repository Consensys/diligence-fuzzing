from unittest.mock import MagicMock, Mock, patch

from click.testing import CliRunner
from pytest import mark
from requests_mock import Mocker

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc import RPCClient
from fuzzing_cli.fuzz.run import IDE
from tests.common import write_config

REFRESH_TOKEN_MALFORMED_ERROR = (
    "Refresh Token is malformed. The format is `<auth_data>::<refresh_token>`"
)


class TestArtifacts:
    def __init__(self, *args, **kwargs):
        pass

    @property
    def payload(self):
        return {"sources": {}, "contracts": {}}

    def generate_payload(self):
        pass


def test_no_keys(tmp_path, truffle_project):
    runner = CliRunner()
    write_config(not_include=["api_key"])
    result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert "API key or Refresh Token were not provided." in result.output
    assert result.exit_code != 0


@patch.object(RPCClient, attribute="contract_exists", new=Mock(return_value=True))
@patch.object(RPCClient, attribute="get_seed_state", new=Mock(return_value={}))
@patch(target="fuzzing_cli.fuzz.run.determine_ide", new=Mock(return_value=IDE.HARDHAT))
@patch(target="fuzzing_cli.fuzz.run.HardhatJob", new=MagicMock())
@patch(target="fuzzing_cli.fuzz.run.FaasClient", new=MagicMock())
@mark.parametrize("in_config,", [False, True])
@mark.parametrize("key_type,", ["api_key", "refresh_token"])
def test_provide_api_key(in_config: bool, key_type: str, tmp_path, truffle_project):
    runner = CliRunner()
    if not in_config:
        write_config(not_include=["api_key"])
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts",
                f"--{key_type.replace('_', '-')}",
                "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
            ],
        )
    else:
        if key_type == "api_key":
            write_config()
        else:
            write_config(not_include=["api_key"], add_refresh_token=True)
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])
    assert result.exit_code == 0
    assert "You can view campaign here:" in result.output


@patch.object(RPCClient, attribute="contract_exists", new=Mock(return_value=True))
@patch.object(RPCClient, attribute="get_seed_state", new=Mock(return_value={}))
@patch(target="fuzzing_cli.fuzz.run.determine_ide", new=Mock(return_value=IDE.HARDHAT))
@patch(target="fuzzing_cli.fuzz.run.HardhatJob", new=MagicMock())
@patch(target="fuzzing_cli.fuzz.run.FaasClient", new=MagicMock())
@mark.parametrize(
    "refresh_token",
    [
        "test",
        "Y2xpZW50X2lkOjphdXRoX2VuZHBvaW50",  # |client_id::auth_endpoint|
        "Y2xpZW50X2lkOjphdXRoX2VuZHBvaW50::",  # |client_id::auth_endpoint|
        "::refresh_token",
        "bHd3dWhzNG81N1ZXN3JZeU5uOUpKWXRXenZJaTJMTEI6Og==::refresh_token",  # |client_id::|::refresh_token
        "bHd3dWhzNG81N1ZXN3JZeU5uOUpKWXRXenZJaTJMTEI=::refresh_token",  # |client_id|::refresh_token
        "Ojpsd3d1aHM0bzU3Vlc3cll5Tm45SkpZdFd6dklpMkxMQg==::refresh_token",  # |::auth_endpoint|::refresh_token
        "Ojpsd3d1aHM0bzU3Vlc3cll5Tm45SkpZdFd6dklpMkxMQg::refresh_token",  # wrongly padded base64 string
    ],
)
def test_wrong_refresh_token(refresh_token: str, tmp_path):
    runner = CliRunner()
    write_config(not_include=["api_key"])
    result = runner.invoke(
        cli, ["run", f"{tmp_path}/contracts", "--refresh-token", refresh_token]
    )
    assert result.exit_code == 2
    assert REFRESH_TOKEN_MALFORMED_ERROR in result.output


@patch.object(RPCClient, attribute="contract_exists", new=Mock(return_value=True))
@patch.object(
    RPCClient,
    attribute="get_seed_state",
    new=Mock(
        return_value={
            "discovery-probability-threshold": 0.0,
            "num-cores": 1,
            "assertion-checking-mode": 1,
            "analysis-setup": {},
        }
    ),
)
@patch(target="fuzzing_cli.fuzz.run.determine_ide", new=Mock(return_value=IDE.HARDHAT))
@patch(target="fuzzing_cli.fuzz.run.HardhatJob", new=Mock(wraps=TestArtifacts))
@mark.parametrize("return_error,", [True, False])
def test_retrieving_api_key(requests_mock: Mocker, return_error: bool, tmp_path):
    requests_mock.real_http = True
    if return_error:
        requests_mock.post(
            "https://example-us.com/oauth/token",
            status_code=403,
            json={"error": "some_error", "error_description": "some description"},
        )
    else:
        requests_mock.post(
            "https://example-us.com/oauth/token",
            status_code=200,
            json={"access_token": "test_access_token"},
        )
        requests_mock.post(
            "http://localhost:9899/api/campaigns/?start_immediately=true",
            status_code=200,
            json={"id": "test-campaign-id"},
        )
    runner = CliRunner()
    write_config(not_include=["api_key"])
    result = runner.invoke(
        cli,
        [
            "run",
            f"{tmp_path}/contracts",
            "--refresh-token",
            "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::test-rt",
        ],
    )

    if return_error:
        assert result.exit_code == 1
        assert "Authorization failed. Error: some_error" in result.output
        req = requests_mock.last_request
    else:
        assert result.exit_code == 0
        assert "You can view campaign here:" in result.output
        req = requests_mock.request_history[0]

    assert req.method == "POST"
    assert req.url == "https://example-us.com/oauth/token"
    assert (
        req.text
        == "grant_type=refresh_token&client_id=test-client-123&refresh_token=test-rt"
    )
