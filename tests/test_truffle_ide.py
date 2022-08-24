import os
from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import Mock, patch

import pytest

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.ide import TruffleArtifacts


class MockedLogger:
    def __init__(self):
        self.debug_messages = []

    def debug(self, msg):
        self.debug_messages.append(msg)


def construct_artifacts() -> TruffleArtifacts:
    with patch.object(
        TruffleArtifacts, "_get_project_sources", new=Mock(return_value={})
    ):
        return TruffleArtifacts(
            options=FuzzingOptions.parse_obj(
                {
                    "build_directory": "build/contracts",
                    "sources_directory": "contracts",
                    "key": "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
                    "deployed_contract_address": "0x0",
                    "targets": ["contracts/Foo.sol"],
                    "truffle_executable_path": "/test/truffle",
                }
            ),
            targets=["contracts/Foo.sol"],
            build_dir=Path("build/contracts"),
            sources_dir=Path("contracts"),
            map_to_original_source=False,
        )


def test_query_db(tmp_path, fake_process, truffle_project):
    os.chdir(tmp_path)

    artifacts = construct_artifacts()
    fake_process.register_subprocess(
        [fake_process.any()], stdout='{"data": {"result": "ok"}}'
    )
    result = artifacts.query_truffle_db('"{test_query: 123}"', f"{tmp_path}/contracts")
    assert result == {"result": "ok"}
    assert len(fake_process.calls) == 1
    assert fake_process.call_count(
        ["/test/truffle", "db", "query", '"{test_query: 123}"']
    )


@pytest.mark.parametrize(
    "stdout, error",
    [
        ("", 'Empty response from the Truffle DB.\nQuery: "test_query" \nError: ""'),
        ("{[", 'JSONDecodeError. \nQuery: "test_query" \nRaw response: "{[\n"'),
        (
            '{"result": "ok"}',
            'Empty response from the Truffle DB.\nQuery: "test_query" \nRaw response: "{"result": "ok"}\n"',
        ),
    ],
)
def test_query_db_errors(
    tmp_path, fake_process, truffle_project, stdout: str, error: str
):
    os.chdir(tmp_path)
    logger = MockedLogger()

    artifacts = construct_artifacts()
    fake_process.register_subprocess(
        ["/test/truffle", "db", "query", "test_query"], stdout=stdout
    )
    with patch("fuzzing_cli.fuzz.ide.truffle.LOGGER", new=logger):
        res = artifacts.query_truffle_db("test_query", f"{tmp_path}/contracts")
        assert res == {}
        assert logger.debug_messages[-1] == error


def test_query_db_no_executable(tmp_path, truffle_project):
    os.chdir(tmp_path)
    logger = MockedLogger()

    def cb(*args, **kwargs):
        raise FileNotFoundError()

    artifacts = construct_artifacts()
    with patch(
        "fuzzing_cli.fuzz.ide.truffle.run", new=Mock(side_effect=cb)
    ), pytest.raises(BuildArtifactsError), patch(
        "fuzzing_cli.fuzz.ide.truffle.LOGGER", new=logger
    ):
        res = artifacts.query_truffle_db("test_query", f"{tmp_path}/contracts")
        assert res == {}

    assert logger.debug_messages[-3:] == [
        'Invoking truffle executable at path "/test/truffle"',
        'Invoking truffle executable at path "truffle"',
        'Invoking truffle executable at path "node_modules/.bin/truffle"',
    ]


def test_query_db_timeout(tmp_path, truffle_project):
    os.chdir(tmp_path)
    logger = MockedLogger()

    def cb(*args, **kwargs):
        raise TimeoutExpired("test", 180)

    artifacts = construct_artifacts()
    with patch("fuzzing_cli.fuzz.ide.truffle.run", new=Mock(side_effect=cb)), patch(
        "fuzzing_cli.fuzz.ide.truffle.LOGGER", new=logger
    ):
        res = artifacts.query_truffle_db("test_query", f"{tmp_path}/contracts")
        assert res == {}

    assert logger.debug_messages[-1] == 'Truffle DB query timeout.\nQuery: "test_query"'
