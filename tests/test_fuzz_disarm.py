import subprocess
from typing import Optional
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from tests.common import assert_is_equal, write_config


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_disarm(tmp_path, scribble_project, fake_process):
    cmd = [
        "scribble",
        "--disarm",
        "--instrumentation-metadata-file=.scribble-arming.meta.json",
        f"{tmp_path}/contracts/VulnerableToken.sol",
    ]
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )
    out = (
        "Moving contracts/VulnerableToken.sol.original to contracts/VulnerableToken.sol\n"
        "Removing contracts/VulnerableToken.sol.instrumented\n"
        "Removing contracts/__scribble_ReentrancyUtils.sol\n"
        "Removing .scribble-arming.meta.json"
    )
    fake_process.register_subprocess(cmd, stdout=out)

    runner = CliRunner()
    command = ["disarm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 0
    assert result.output == f"{out}\n"
    assert len(fake_process.calls) == 1
    process_command = fake_process.calls[0]
    assert process_command == cmd


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_disarm_no_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **scribble_project,
        not_include=["targets"],
    )

    fake_process.register_subprocess([fake_process.any()], stdout="")
    runner = CliRunner()
    command = ["disarm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 2
    assert "Invalid config: Targets not provided." in result.output
    assert len(fake_process.calls) == 0


@pytest.mark.parametrize(
    "error",
    [
        "FileNotFoundError: [Errno 2] No such file or directory: 'scribble'",
        'Unable to disarm: instrumentation metadata file "instrumentation.scribble.json" does not exist.',
    ],
)
@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_disarm_process_error(
    tmp_path, scribble_project, fake_process, error: str
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )

    fake_process.register_subprocess(
        [fake_process.any()], stdout="", returncode=1, stderr=error
    )
    runner = CliRunner()
    command = ["disarm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 1
    assert (
        f"Error: ScribbleError:\nThere was an error un-instrumenting your contracts with scribble:\n{error}"
        in result.output
    )
    assert len(fake_process.calls) == 1


@pytest.mark.parametrize(
    "scribble_path, in_config",
    [
        (None, False),
        ("scribble", False),
        ("scribble_test", False),
        ("scribble_test", True),
    ],
)
def test_fuzz_disarm_unknown_scribble_path(
    tmp_path, scribble_project, scribble_path: Optional[str], in_config: Optional[bool]
):
    if scribble_path and in_config:
        write_config(
            config_path=f"{tmp_path}/.fuzz.yml",
            base_path=str(tmp_path),
            **{**scribble_project, "targets": ["contracts/VulnerableToken.sol"]},
            scribble_path=scribble_path,
        )

    def cb(*args, **kwargs):
        raise FileNotFoundError("executable not found")

    runner = CliRunner()
    command = ["disarm"]
    if scribble_path and not in_config:
        command += ["--scribble-path", scribble_path]
    command += ["contracts/VulnerableToken.sol"]

    with patch.object(subprocess, "run") as run_mock:
        run_mock.side_effect = cb
        result = runner.invoke(cli, command)

    assert (
        f"Scribble not found at path \"{(scribble_path or 'scribble')}\". "
        f"Please provide scribble path using either `--scribble-path` option to `fuzz disarm` command "
        f"or set one in config" in result.output
    )
    assert result.exit_code == 2


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_disarm_folder_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**scribble_project, "targets": ["contracts"]},
    )

    fake_process.register_subprocess([fake_process.any()], stdout="success")
    runner = CliRunner()
    command = ["disarm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 0
    assert result.output == "success\n"
    assert len(fake_process.calls) == 1
    assert_is_equal(
        fake_process.calls[0],
        [
            "scribble",
            "--disarm",
            "--instrumentation-metadata-file=.scribble-arming.meta.json",
            f"{tmp_path}/contracts/Migrations.sol",
            f"{tmp_path}/contracts/VulnerableToken.sol",
        ],
    )


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_disarm_empty_folder_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**scribble_project, "targets": ["contracts-123"]},
    )

    fake_process.register_subprocess([fake_process.any()], stdout="success")
    runner = CliRunner()
    command = ["disarm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 1
    assert (
        f"Error: ScribbleError:\nThere was an error un-instrumenting your contracts with scribble:\n"
        f"No files to instrument at provided targets"
    )
    assert len(fake_process.calls) == 0
