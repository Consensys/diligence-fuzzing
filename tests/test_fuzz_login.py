from unittest.mock import MagicMock, Mock, patch

from click.testing import CliRunner
from pytest import mark
from requests_mock import Mocker

from fuzzing_cli.cli import cli
from tests.common import write_config

KEY_MALFORMED_ERROR = "Error: API key is malformed. The format is `<auth_data>::<refresh_token>`. If you don't have an API key, please visit https://fuzzing.diligence.tools/keys to obtain one. If you don't have an active subscription, please visit https://fuzzing.diligence.tools/subscription to obtain a subscription."


class ArtifactMock:
    def __init__(self, *args, **kwargs):
        self.sources = {}
        self.contracts = {}

    @classmethod
    def get_name(cls):
        return "hardhat"

    def validate(self):
        return None

    @staticmethod
    def instance_for_targets(instance, targets):
        return instance


class ArtifactsMock:
    def __init__(self, *args, **kwargs):
        pass

    @property
    def payload(self):
        return {"sources": {}, "contracts": {}}

    def generate_payload(self):
        pass


class CorpusRepoMock:
    def __init__(self, *args, **kwargs):
        self.validation_errors = []
        self.source_targets = []

    @property
    def seed_state(self):
        return {
            "discovery-probability-threshold": 0.0,
            "num-cores": 1,
            "assertion-checking-mode": 1,
            "analysis-setup": {},
        }


def test_no_keys(tmp_path, truffle_project):
    runner = CliRunner()
    write_config(ide="truffle", not_include=["api_key"])
    result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])

    assert (
        "Error: Invalid config: API key not provided. To use this tool, you must obtain an API key from https://fuzzing.diligence.tools/keys."
        in result.output
    )
    assert result.exit_code != 0


@patch(
    target="fuzzing_cli.fuzz.ide.repository.IDERepository.detect_ide",
    new=Mock(return_value=ArtifactMock),
)
@patch(target="fuzzing_cli.fuzz.run.FaasClient", new=MagicMock())
@patch("fuzzing_cli.fuzz.run.CorpusRepository", new=CorpusRepoMock)
@mark.parametrize("as_env", [False, True])
def test_provide_api_key(as_env: bool, tmp_path, truffle_project, monkeypatch):
    runner = CliRunner()
    write_config()
    if not as_env:
        monkeypatch.delenv("FUZZ_API_KEY", raising=False)
        result = runner.invoke(
            cli,
            [
                "run",
                f"{tmp_path}/contracts",
                f"--key",
                "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
            ],
        )
    else:
        monkeypatch.setenv(
            "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
        )
        result = runner.invoke(cli, ["run", f"{tmp_path}/contracts"])
    assert result.exit_code == 0
    assert "You can view campaign here:" in result.output


@patch(
    target="fuzzing_cli.fuzz.ide.repository.IDERepository.detect_ide",
    new=Mock(return_value=ArtifactMock),
)
@patch("fuzzing_cli.fuzz.run.CorpusRepository", new=CorpusRepoMock)
@patch(target="fuzzing_cli.fuzz.run.FaasClient", new=MagicMock())
@mark.parametrize(
    "key",
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
def test_validate_api_key(key: str, tmp_path):
    runner = CliRunner()
    write_config()
    result = runner.invoke(cli, ["run", f"{tmp_path}/contracts", "-k", key])
    assert result.exit_code == 2
    assert KEY_MALFORMED_ERROR in result.output


@patch(
    target="fuzzing_cli.fuzz.ide.repository.IDERepository.detect_ide",
    new=Mock(return_value=ArtifactMock),
)
@patch("fuzzing_cli.fuzz.run.CorpusRepository", new=CorpusRepoMock)
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
    write_config()
    result = runner.invoke(
        cli,
        [
            "run",
            f"{tmp_path}/contracts",
            "--key",
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
