import subprocess
from typing import List, Optional
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from tests.common import assert_is_equal, write_config


@pytest.mark.parametrize(
    "remappings, solc_version, _assert",
    [
        (None, None, None),
        (
            ["@openzeppelin:node_modules/@openzeppelin", "@a:node_modules/b/a"],
            "0.8.10",
            True,
        ),
        (
            ["@openzeppelin:node_modules/@openzeppelin", "@a:node_modules/b/a"],
            "0.8.10",
            False,
        ),
    ],
)
@pytest.mark.parametrize("params_in_config", [True, False])
@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm(
    tmp_path,
    scribble_project,
    fake_process,
    remappings: Optional[List[str]],
    solc_version: Optional[str],
    _assert: Optional[bool],
    params_in_config: bool,
):
    cmd = [
        "scribble",
        "--arm",
        "--output-mode=files",
        "--instrumentation-metadata-file=.scribble-arming.meta.json",
        fake_process.any(),
        f"{tmp_path}/contracts/VulnerableToken.sol",
    ]
    if params_in_config:
        write_config(
            config_path=f"{tmp_path}/.fuzz.yml",
            base_path=str(tmp_path),
            **scribble_project,
            remappings=remappings,
            solc_version=solc_version,
            _assert=_assert,
        )
    else:
        write_config(
            config_path=f"{tmp_path}/.fuzz.yml",
            base_path=str(tmp_path),
            **scribble_project,
        )
    out = (
        "Found 4 annotations in 1 different files.\n"
        "contracts/VulnerableToken.sol -> contracts/VulnerableToken.sol.instrumented\n"
        "Copying contracts/VulnerableToken.sol to contracts/VulnerableToken.sol.original\n"
        "Copying contracts/VulnerableToken.sol.instrumented to contracts/VulnerableToken.sol"
    )
    fake_process.register_subprocess(cmd, stdout=out)
    runner = CliRunner()
    command = ["arm"]
    if remappings and not params_in_config:
        for r in remappings:
            command.extend(["--remap-import", r])
    if solc_version and not params_in_config:
        command.extend(["--solc-version", solc_version])
    if _assert and not params_in_config:
        command.extend(["--assert"])
    result = runner.invoke(cli, command)

    assert result.exit_code == 0
    assert result.output == f"{out}\n"
    assert len(fake_process.calls) == 1
    process_command = fake_process.calls[0]
    assert process_command[0:4] == cmd[0:4]

    if remappings:
        assert f"--path-remapping={';'.join(remappings)}" in process_command
    else:
        assert "--path-remapping" not in process_command

    if solc_version:
        assert f"--compiler-version={solc_version}" in process_command
    else:
        assert "--compiler-version" not in process_command

    if _assert:
        assert "--no-assert" not in process_command
    else:
        assert "--no-assert" in process_command


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_no_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **scribble_project,
        not_include=["targets"],
    )

    fake_process.register_subprocess([fake_process.any()], stdout="")
    runner = CliRunner()
    command = ["arm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 2
    assert "Invalid config: Targets not provided." in result.output
    assert len(fake_process.calls) == 0


@pytest.mark.parametrize(
    "error",
    [
        "FileNotFoundError: [Errno 2] No such file or directory: 'scribble'",
        "Compile errors encountered:\n"
        "SolcJS 0.8.13:\n"
        "ParserError: Source file requires different compiler version (current compiler is "
        "0.8.13+commit.abaa5c0e.Darwin.appleclang) - note that nightly builds are considered "
        "to be strictly less than the released version\n"
        " --> contracts/__scribble_ReentrancyUtils.sol:3:1:\n  |\n"
        "3 | pragma solidity 0.8.5;\n  | ^^^^^^^^^^^^^^^^^^^^^^",
    ],
)
@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_process_error(tmp_path, scribble_project, fake_process, error: str):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )

    fake_process.register_subprocess(
        [fake_process.any()], stdout="", returncode=1, stderr=error
    )
    runner = CliRunner()
    command = ["arm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 1
    assert (
        f"Error: ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n{error}"
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
def test_fuzz_arm_unknown_scribble_path(
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
    command = ["arm"]
    if scribble_path and not in_config:
        command += ["--scribble-path", scribble_path]
    command += ["contracts/VulnerableToken.sol"]

    with patch.object(subprocess, "run") as run_mock:
        run_mock.side_effect = cb
        result = runner.invoke(cli, command)

    assert (
        f"Scribble not found at path \"{(scribble_path or 'scribble')}\". "
        f"Please provide scribble path using either `--scribble-path` option to `fuzz arm` command "
        f"or set one in config" in result.output
    )
    assert result.exit_code == 2


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_folder_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**scribble_project, "targets": ["contracts"]},
    )

    fake_process.register_subprocess([fake_process.any()], stdout="success")
    runner = CliRunner()
    command = ["arm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 0
    assert result.output == "success\n"
    assert len(fake_process.calls) == 1
    assert_is_equal(
        fake_process.calls[0],
        [
            "scribble",
            "--arm",
            "--output-mode=files",
            "--instrumentation-metadata-file=.scribble-arming.meta.json",
            "--debug-events",
            "--no-assert",
            f"{tmp_path}/contracts/Migrations.sol",
            f"{tmp_path}/contracts/VulnerableToken.sol",
        ],
    )


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_empty_folder_targets(tmp_path, scribble_project, fake_process):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml",
        base_path=str(tmp_path),
        **{**scribble_project, "targets": ["contracts-123"]},
    )

    fake_process.register_subprocess([fake_process.any()], stdout="success")
    runner = CliRunner()
    command = ["arm"]
    result = runner.invoke(cli, command)

    assert result.exit_code == 1
    assert (
        f"Error: ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n"
        f"No files to instrument at provided targets"
    )
    assert len(fake_process.calls) == 0
