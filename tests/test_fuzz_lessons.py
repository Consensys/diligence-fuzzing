import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from tests.common import get_test_case, mocked_rpc_client
from tests.common import write_config as __write_config


def write_config(tmp_path: Path):
    __write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        build_directory="artifacts",
        targets="contracts/LessonTestContract.sol",
        deployed_contract_address="0xc2E17c0b175402d669Baa4DBDF3C5Ea3CF010cAC",
    )


@pytest.mark.parametrize("description", [None, "test description"])
def test_start(tmp_path: Path, hardhat_fuzzing_lessons_project, description: str):
    write_config(tmp_path)

    with mocked_rpc_client(
        get_test_case("testdata/hardhat_fuzzing_lessons_project/blocks.json")
    ):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["lesson", "start"]
            + (["--description", description] if description is not None else []),
        )

    assert result.exit_code == 0

    with tmp_path.joinpath(".fuzzing_lessons.json").open("r") as f:
        lesson_data = json.load(f)
    assert lesson_data == {
        "runningLesson": {
            "numberOfBlocks": 2,
            "description": description or "my lesson",
        },
        "lessons": [],
    }


def test_already_started(api_key, tmp_path: Path, hardhat_fuzzing_lessons_project):
    write_config(tmp_path)

    with mocked_rpc_client(
        get_test_case("testdata/hardhat_fuzzing_lessons_project/blocks.json")
    ):
        runner = CliRunner()
        result = runner.invoke(cli, ["lesson", "start"])
        assert result.exit_code == 0
        result = runner.invoke(cli, ["lesson", "start"])

    assert result.exit_code == 1
    assert result.output == "Error: Another fuzzing lesson is running\n"
    assert tmp_path.joinpath(".fuzzing_lessons.json").exists() is True


def test_stop(api_key, tmp_path, hardhat_fuzzing_lessons_project):
    write_config(tmp_path)

    with mocked_rpc_client(
        get_test_case("testdata/hardhat_fuzzing_lessons_project/blocks.json")
    ):
        runner = CliRunner()
        runner.invoke(cli, ["lesson", "start"])

    blocks_after_lesson = get_test_case(
        "testdata/hardhat_fuzzing_lessons_project/lessons.json"
    )

    with mocked_rpc_client(blocks_after_lesson):
        runner = CliRunner()
        result = runner.invoke(cli, ["lesson", "stop"])

    assert result.exit_code == 0

    with tmp_path.joinpath(".fuzzing_lessons.json").open("r") as f:
        lesson_data = json.load(f)
    assert lesson_data == {
        "runningLesson": None,
        "lessons": [
            {
                "description": "my lesson",
                "transactions": [
                    [
                        {
                            "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                            "blockCoinbase": "0x0000000000000000000000000000000000000000",
                            "blockDifficulty": "0x0",
                            "blockGasLimit": "0x6691b7",
                            "blockNumber": "0x2",
                            "blockTime": "0x62bd7444",
                            "gasLimit": "0x3381a",
                            "gasPrice": "0x4a817c800",
                            "input": "0x3f81a2c0000000000000000000000000000000000000000000000000000000000000002a",
                            "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                            "value": "0x0",
                        },
                        {
                            "address": "0xc2e17c0b175402d669baa4dbdf3c5ea3cf010cac",
                            "blockCoinbase": "0x0000000000000000000000000000000000000000",
                            "blockDifficulty": "0x0",
                            "blockGasLimit": "0x6691b7",
                            "blockNumber": "0x3",
                            "blockTime": "0x62bd7444",
                            "gasLimit": "0x6691b7",
                            "gasPrice": "0x9184e72a000",
                            "input": "0x9507d39abeced09521047d05b8960b7e7bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2",
                            "origin": "0xc68b3325948b2c31f9224b71e5233cc071ca39cb",
                            "value": "0x0",
                        },
                    ]
                ],
            }
        ],
    }


def test_stop_no_transactions_in_lesson(
    api_key, tmp_path, hardhat_fuzzing_lessons_project
):
    write_config(tmp_path)

    with mocked_rpc_client(
        get_test_case("testdata/hardhat_fuzzing_lessons_project/blocks.json")
    ):
        runner = CliRunner()
        runner.invoke(cli, ["lesson", "start", "--description", "test-lesson"])

    blocks_after_lesson = get_test_case(
        "testdata/hardhat_fuzzing_lessons_project/blocks.json"
    )

    with mocked_rpc_client(blocks_after_lesson):
        runner = CliRunner()
        result = runner.invoke(cli, ["lesson", "stop"])

    assert result.exit_code == 0
    with tmp_path.joinpath(".fuzzing_lessons.json").open("r") as f:
        lesson_data = json.load(f)
    assert lesson_data == {
        "runningLesson": None,
        "lessons": [{"description": "test-lesson", "transactions": [[]]}],
    }


@pytest.mark.parametrize("command", ["stop", "abort"])
def test_not_started(
    api_key, tmp_path: Path, hardhat_fuzzing_lessons_project, command: str
):
    write_config(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["lesson", command])

    assert result.exit_code == 1
    assert result.output == "Error: No fuzzing lesson is running\n"


def test_abort(api_key, tmp_path, hardhat_fuzzing_lessons_project):
    write_config(tmp_path)

    with mocked_rpc_client(
        get_test_case("testdata/hardhat_fuzzing_lessons_project/blocks.json")
    ):
        runner = CliRunner()
        runner.invoke(cli, ["lesson", "start"])

    runner = CliRunner()
    result = runner.invoke(cli, ["lesson", "abort"])

    assert result.exit_code == 0

    with tmp_path.joinpath(".fuzzing_lessons.json").open("r") as f:
        lesson_data = json.load(f)
    assert lesson_data == {"runningLesson": None, "lessons": []}
