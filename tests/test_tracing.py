import os
import platform
from unittest.mock import Mock, patch

from click.testing import CliRunner

from fuzzing_cli import __version__
from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.analytics import Session
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.ide import FoundryArtifacts
from tests.common import (
    assert_is_equal,
    get_test_case,
    mocked_rpc_client,
    omit_keys,
    write_config,
)


def test_operations(
    foundry_project,
    tmp_path,
    fake_process,
    monkeypatch,
):
    Session.give_consent(True)

    os.chdir(tmp_path)
    monkeypatch.setenv(
        "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    )
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **foundry_project,
    )
    fake_process.register_subprocess([fake_process.any()], stdout="")
    runner = CliRunner()

    result = runner.invoke(cli, ["arm"])
    assert result.exit_code == 0

    blocks = get_test_case("testdata/foundry_project/blocks.json")
    contracts = get_test_case("testdata/foundry_project/contracts.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes) as m, patch.object(
        FaasClient, "start_faas_campaign"
    ), patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        m.post(
            "https://fuzzing.diligence.tools/api/analytics",
            json={"success": True},
            status_code=200,
        )
        result = runner.invoke(cli, ["run"])
        assert result.exit_code == 0

        session_post = m.request_history[-1]
        session_post_data = session_post.json()
        assert (
            session_post.url == "https://fuzzing.diligence.tools/api/analytics/sessions"
        )
        assert session_post.method == "POST"
        assert_is_equal(
            list(session_post_data.keys()),
            [
                "deviceId",
                "sessionId",
                "system",
                "release",
                "machine",
                "pythonVersion",
                "pythonImplementation",
                "fuzzingCliVersion",
                "rpcNodeKind",
                "rpcNodeVersion",
                "ciMode",
                "userId",
                "functionCalls",
            ],
        )

        assert [
            omit_keys(d, ["duration"]) for d in session_post_data["functionCalls"]
        ] == [
            {
                "functionName": "fuzz_arm",
                "result": "success",
                "context": {},
            },
            {
                "functionName": "fuzz_run",
                "result": "success",
                "context": {},
            },
        ]


def test_capture_exception(
    foundry_project,
    tmp_path,
    monkeypatch,
):
    Session.give_consent(True)

    os.chdir(tmp_path)
    monkeypatch.setenv(
        "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    )
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **foundry_project,
    )
    runner = CliRunner()

    blocks = get_test_case("testdata/foundry_project/blocks.json")
    contracts = get_test_case("testdata/foundry_project/contracts.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes) as m, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ):
        m.post(
            "https://fuzzing.diligence.tools/api/analytics",
            json={"success": True},
            status_code=200,
        )

        start_faas_campaign_mock.side_effect = Exception("test exception")
        result = runner.invoke(cli, ["run"], input="y\n")
        assert result.exit_code == 1

        session_post = m.request_history[-1]
        session_post_data = session_post.json()
        assert (
            session_post.url == "https://fuzzing.diligence.tools/api/analytics/sessions"
        )
        assert session_post.method == "POST"

        function_calls = [
            omit_keys(d, ["stackTrace"]) for d in session_post_data["functionCalls"]
        ]
        assert all("stackTrace" in d for d in session_post_data["functionCalls"])
        assert [omit_keys(d, ["duration"]) for d in function_calls] == [
            {
                "functionName": "fuzz_run",
                "result": "exception",
                "errorMessage": "Unhandled exception - test exception",
                "errorType": "ClickException",
                "context": {},
            }
        ]


def test_report_crash(
    foundry_project,
    tmp_path,
    monkeypatch,
):
    Session.give_consent(True)
    os.chdir(tmp_path)
    monkeypatch.setenv(
        "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    )
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **foundry_project,
    )
    runner = CliRunner()

    blocks = get_test_case("testdata/foundry_project/blocks.json")
    contracts = get_test_case("testdata/foundry_project/contracts.json")
    codes = {
        contract["address"].lower(): contract["deployedBytecode"]
        for contract in contracts.values()
    }

    with mocked_rpc_client(blocks, codes) as m, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch.object(
        FoundryArtifacts,
        "instance_for_targets",
        new=Mock(side_effect=Exception("test exception")),
    ):
        m.post(
            "https://fuzzing.diligence.tools/api/analytics",
            json={"success": True},
            status_code=200,
        )
        m.post(
            "https://fuzzing.diligence.tools/api/analytics/crash-reports",
            json={"success": True},
            status_code=200,
        )

        start_faas_campaign_mock.side_effect = Exception("test exception")
        result = runner.invoke(cli, ["run"], input="y\n")
        assert result.exit_code == 0
        assert (
            result.output == "Oops! 🙊 Something didn't go as planned. "
            "Please see details below for more information: "
            "Exception: test exception\n"
            "Do you want to report this error? [Y/n]: y\n"
        )

        crash_report_post = m.request_history[-2]
        crash_report_post_data = crash_report_post.json()

        session_post = m.request_history[-1]
        session_post_data = session_post.json()

        assert (
            crash_report_post.url
            == "https://fuzzing.diligence.tools/api/analytics/crash-reports"
        )
        assert crash_report_post.method == "POST"
        assert omit_keys(
            crash_report_post_data,
            ["stackTrace", "stackFrames", "deviceId", "sessionId", "errorCulprit"],
        ) == {
            "userId": "test-user",
            "errorMessage": "test exception",
            "errorType": "Exception",
            "context": {},
            "ciMode": False,
            "fuzzingCliVersion": __version__,
            "machine": platform.machine(),
            "pythonImplementation": platform.python_implementation(),
            "pythonVersion": platform.python_version(),
            "release": platform.release(),
            "rpcNodeKind": "test",
            "rpcNodeVersion": "test/0.0.1",
            "system": platform.system(),
        }

        assert_is_equal(
            list(crash_report_post_data.keys()),
            [
                "deviceId",
                "userId",
                "sessionId",
                "errorType",
                "errorMessage",
                "errorCulprit",
                "stackTrace",
                "stackFrames",
                "context",
                "ciMode",
                "fuzzingCliVersion",
                "machine",
                "pythonImplementation",
                "pythonVersion",
                "release",
                "rpcNodeKind",
                "rpcNodeVersion",
                "system",
            ],
        )

        assert (
            session_post.url == "https://fuzzing.diligence.tools/api/analytics/sessions"
        )
        assert session_post.method == "POST"
        function_calls = [
            omit_keys(d, ["stackTrace"]) for d in session_post_data["functionCalls"]
        ]
        assert [omit_keys(d, ["duration"]) for d in function_calls] == [
            {
                "functionName": "fuzz_run",
                "result": "exception",
                "errorMessage": "test exception",
                "errorType": "Exception",
                "context": {},
            }
        ]
