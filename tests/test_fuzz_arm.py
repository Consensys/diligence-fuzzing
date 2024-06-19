import shutil
import subprocess
from pathlib import Path
from typing import List, Optional
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.util import executable_command
from tests.common import (
    _construct_scribble_error_message,
    assert_is_equal,
    write_config,
)


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
        *executable_command("scribble"),
        "--arm",
        "--output-mode=files",
        "--instrumentation-metadata-file=.scribble-arming.meta.json",
        fake_process.any(),
        str(Path(f"{tmp_path}/contracts/VulnerableToken.sol")),
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
def test_fuzz_arm_no_targets(tmp_path: Path, scribble_project, fake_process, ci_mode):
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

    assert result.exit_code == 1
    assert (
        result.output == "⚠️ Targets were not provided but the following files can "
        "be set as targets to be armed:\n"
        f"  ◦ {tmp_path.joinpath('contracts/Migrations.sol')}\n  ◦ {tmp_path.joinpath('contracts/VulnerableToken.sol')}\n"
        "Error: ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n"
        "No files to instrument at provided targets\n"
    )
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
        f"Error: ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n{error}\n"
        == result.output
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

    assert _construct_scribble_error_message(f"executable not found\n") in result.output
    assert result.exit_code == 1


@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_folder_targets(tmp_path: Path, scribble_project, fake_process):
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
            *executable_command("scribble"),
            "--arm",
            "--output-mode=files",
            "--instrumentation-metadata-file=.scribble-arming.meta.json",
            "--debug-events",
            "--no-assert",
            f"{tmp_path.joinpath('contracts/Migrations.sol')}",
            f"{tmp_path.joinpath('contracts/VulnerableToken.sol')}",
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
        f"No files to instrument at provided targets\n"
    ) == result.output
    assert len(fake_process.calls) == 0


@pytest.mark.parametrize("smart_mode", [True, False])
@pytest.mark.parametrize("ci_mode_flag", [True, False])
@pytest.mark.parametrize("accept_suggestions", [True, False])
@patch("pathlib.Path.exists", new=Mock(return_value=True))
def test_fuzz_arm_smart_mode(
    tmp_path,
    scribble_project,
    fake_process,
    monkeypatch,
    smart_mode: bool,
    ci_mode_flag: bool,
    accept_suggestions: bool,
):
    monkeypatch.delenv("FUZZ_CONFIG_FILE", raising=False)
    monkeypatch.setenv("FUZZ_SMART_MODE", "true" if smart_mode else "false")
    monkeypatch.setenv("FUZZ_CI_MODE", "true" if ci_mode_flag else "false")

    cmd = [
        *executable_command("scribble"),
        "--arm",
        "--output-mode=files",
        "--instrumentation-metadata-file=.scribble-arming.meta.json",
        fake_process.any(),
        f"{tmp_path.joinpath('contracts/VulnerableToken.sol')}",
    ]

    out = (
        "Found 4 annotations in 1 different files.\n"
        "contracts/VulnerableToken.sol -> contracts/VulnerableToken.sol.instrumented\n"
        "Copying contracts/VulnerableToken.sol to contracts/VulnerableToken.sol.original\n"
        "Copying contracts/VulnerableToken.sol.instrumented to contracts/VulnerableToken.sol"
    )
    fake_process.register_subprocess(cmd, stdout=out)
    runner = CliRunner()
    result = runner.invoke(cli, ["arm"], input="y\n" if accept_suggestions else "n\n")
    if not smart_mode:
        suggestion = (
            "⚠️ Targets were not provided but the following files can be set as targets to be armed:\n"
            f"  ◦ {tmp_path.joinpath('contracts/Migrations.sol')}\n"
            f"  ◦ {tmp_path.joinpath('contracts/VulnerableToken.sol')}"
        )
        warnings = (
            "Warning: Build directory not specified. Using IDE defaults. "
            "For a proper seed state check please set one.\n"
            "Warning: Sources directory not specified. Using IDE defaults. "
            "For a proper seed state check please set one."
        )
        scribble_error = (
            f"Error: ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n"
            "No files to instrument at provided targets\n"
        )

        if ci_mode_flag:
            assert result.exit_code == 1
            assert result.output == f"{warnings}\n{suggestion}\n{scribble_error}"
        elif not accept_suggestions:
            assert result.exit_code == 1
            assert (
                result.output == f"{warnings}\n"
                f"[?] {suggestion}\nAdd them to targets? [Y/n]: n\n{suggestion}\n"
                f"{scribble_error}"
            )
        else:
            # accepted suggestions
            assert result.exit_code == 0
            assert (
                result.output == f"{warnings}\n"
                f"[?] {suggestion}\nAdd them to targets? [Y/n]: y\n{out}\n"
            )
            assert len(fake_process.calls) == 1
            process_command = fake_process.calls[0]
            assert process_command[0:4] == cmd[0:4]
            assert "--no-assert" in process_command
    else:
        # with smart mode enabled, suggestions will be auto-applied
        assert result.exit_code == 0
        assert result.output == f"{out}\n"
        assert len(fake_process.calls) == 1
        process_command = fake_process.calls[0]
        assert process_command[0:4] == cmd[0:4]
        assert "--no-assert" in process_command
