import subprocess
from pathlib import Path
from typing import List
from unittest.mock import Mock, patch

import pytest
import solcx
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.config.utils import parse_config
from fuzzing_cli.fuzz.faas import FaasClient
from tests.common import assert_is_equal, write_config
from tests.testdata.quickcheck_project.echidna.utils import (
    get_compilation_artifacts,
    get_processed_payload,
)


@pytest.mark.parametrize(
    "targets",
    [
        ["contracts"],
        [
            "contracts/SecondVulnerableTokenTest.sol",
            "contracts/VulnerableTokenTest.sol",
        ],
    ],
)
def test_fuzz_auto(tmp_path: Path, truffle_echidna_project, fake_process, targets):
    fake_process.register_subprocess([fake_process.any()])

    with patch(
        "fuzzing_cli.fuzz.quickcheck.determine_ide"
    ) as determine_ide_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_targets"
    ) as determine_targets_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_cpu_cores"
    ) as determine_cpu_cores_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_campaign_name"
    ) as determine_campaign_name_mock:
        determine_ide_mock.return_value = truffle_echidna_project["ide"]
        determine_targets_mock.return_value = [f"{tmp_path}/{t}" for t in targets]
        determine_cpu_cores_mock.return_value = 1
        determine_campaign_name_mock.return_value = "test-campaign"

        runner = CliRunner()
        result = runner.invoke(cli, ["auto"])

    assert result.exit_code == 0

    assert len(fake_process.calls) == 1
    assert fake_process.calls[0] == ["scribble-generate", "--targets"] + [
        f"{tmp_path}/{t}" for t in targets
    ]

    config = parse_config(
        tmp_path.joinpath(f".fuzz_{tmp_path.name.lower().replace('-', '_')}.yml")
    )
    assert config["fuzz"].get("ide") == "truffle"
    assert_is_equal(
        list(config["fuzz"].get("targets")),
        [
            f"{tmp_path}/contracts/SecondVulnerableTokenTest.sol",
            f"{tmp_path}/contracts/VulnerableTokenTest.sol",
        ],
    )
    assert config["fuzz"].get("quick_check") == True
    assert config["fuzz"].get("number_of_cores") == 1
    assert config["fuzz"].get("campaign_name_prefix") == "test-campaign"
    assert config["analyze"].get("remappings") is None
    assert config["analyze"].get("solc-version") is None
    assert config["analyze"].get("scribble-path") == "scribble"
    assert config["analyze"].get("no-assert") is None


def test_no_annotated_contracts(tmp_path, truffle_echidna_project, fake_process):
    fake_process.register_subprocess([fake_process.any()])

    with patch(
        "fuzzing_cli.fuzz.quickcheck.determine_ide",
        new=Mock(return_value=truffle_echidna_project["ide"]),
    ), patch(
        "fuzzing_cli.fuzz.quickcheck.determine_targets"
    ) as determine_targets_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_cpu_cores", new=Mock(return_value=1)
    ), patch(
        "fuzzing_cli.fuzz.quickcheck.determine_campaign_name",
        new=Mock(return_value="test-campaign"),
    ):
        determine_targets_mock.return_value = [
            f"{tmp_path}/contracts/VulnerableToken.sol"
        ]
        runner = CliRunner()
        result = runner.invoke(cli, ["auto"])

    assert result.exit_code == 2
    assert "No target contains `echidna` or `ds-test` test cases" in result.output

    assert len(fake_process.calls) == 1
    assert fake_process.calls[0] == [
        "scribble-generate",
        "--targets",
        f"{tmp_path}/contracts/VulnerableToken.sol",
    ]


@pytest.mark.parametrize(
    "retcode, stderr, exc, output",
    [
        (
            127,
            "Annotation Error",
            None,
            "Error: QuickCheckError: Annotating failed\nDetail: \nAnnotation Error\n",
        ),
        (
            0,
            "",
            FileNotFoundError(),
            f"Error: QuickCheckError: scribble-generator invocation error. Tried executable at scribble-generate. "
            f"Please make sure `scribble-generator` is installed properly or provide path "
            f"to the executable using `--scribble-generator-path` option to `fuzz auto`\n",
        ),
        (
            0,
            "",
            OSError(),
            f"Error: QuickCheckError: Unhandled Exception\nDetail: OSError()\n",
        ),
    ],
)
def test_annotation_errors(
    tmp_path, truffle_echidna_project, fake_process, retcode, stderr, exc, output
):
    fake_process.register_subprocess(
        [fake_process.any()], returncode=retcode, stderr=stderr
    )

    with patch(
        "fuzzing_cli.fuzz.quickcheck.determine_ide",
        new=Mock(return_value=truffle_echidna_project["ide"]),
    ), patch(
        "fuzzing_cli.fuzz.quickcheck.determine_targets"
    ) as determine_targets_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_cpu_cores", new=Mock(return_value=1)
    ), patch(
        "fuzzing_cli.fuzz.quickcheck.determine_campaign_name",
        new=Mock(return_value="test-campaign"),
    ):
        determine_targets_mock.return_value = [f"{tmp_path}/contracts"]
        if exc:
            with patch.object(subprocess, "run", new=Mock(side_effect=exc)):
                runner = CliRunner()
                result = runner.invoke(cli, ["auto"])
        else:
            runner = CliRunner()
            result = runner.invoke(cli, ["auto"])
            assert len(fake_process.calls) == 1
            assert fake_process.calls[0] == [
                "scribble-generate",
                "--targets",
                f"{tmp_path}/contracts",
            ]

    assert result.exit_code == 1
    assert result.output == output


@pytest.mark.parametrize(
    "targets",
    [
        [
            "contracts/VulnerableTokenTest.sol",
            "contracts/SecondVulnerableTokenTest.sol",
        ],
        ["contracts/VulnerableTokenTest.sol"],
        ["contracts/SecondVulnerableTokenTest.sol"],
    ],
)
@pytest.mark.parametrize("truffle_echidna_project", ("armed",), indirect=True)
@pytest.mark.parametrize(
    "corpus_target", ["crp_30f45fac74c04182b023ead4f0ddb709", None]
)
def test_fuzz_run(
    api_key,
    tmp_path: Path,
    truffle_echidna_project,
    fake_process,
    targets: List[str],
    corpus_target,
):
    write_config(
        base_path=str(tmp_path),
        **{**truffle_echidna_project, "targets": targets},
        quick_check=True,
        corpus_target=corpus_target,
    )

    fake_process.register_subprocess([fake_process.any()])

    with patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch.object(
        solcx, "compile_standard"
    ) as compile_standard_mock, patch.object(
        solcx, "get_installed_solc_versions"
    ) as get_installed_solc_versions_mock, patch.object(
        solcx, "install_solc"
    ) as install_solc_mock, patch.object(
        solcx, "set_solc_version"
    ) as set_solc_version_mock:
        compile_standard_mock.return_value = get_compilation_artifacts(targets)
        get_installed_solc_versions_mock.return_value = []
        install_solc_mock.return_value = None
        set_solc_version_mock.return_value = None

        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id
        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

    assert result.exit_code == 0

    set_solc_version_mock.assert_called_once_with("v0.8.1", silent=True)

    _sources = {f"{tmp_path}/{t}": {"urls": [f"{tmp_path}/{t}"]} for t in targets}
    compile_standard_mock.assert_called_once_with(
        solc_binary=None,
        input_data={
            "language": "Solidity",
            "sources": _sources,
            "settings": {
                "remappings": [
                    f"openzeppelin-solidity/={tmp_path}/node_modules/openzeppelin-solidity/",
                    f"openzeppelin-zos/={tmp_path}/node_modules/openzeppelin-zos/",
                    f"zos-lib/={tmp_path}/node_modules/zos-lib/",
                ],
                "outputSelection": {
                    "*": {
                        "*": [
                            "evm.bytecode.object",
                            "evm.bytecode.sourceMap",
                            "evm.deployedBytecode.object",
                            "evm.deployedBytecode.sourceMap",
                        ],
                        "": ["ast"],
                    }
                },
                "optimizer": {"enabled": True, "runs": 200},
            },
        },
        allow_paths=[str(tmp_path)],
    )

    assert len(fake_process.calls) == 1
    assert fake_process.calls[0] == (
        [
            "scribble",
            "--arm",
            "--output-mode=files",
            "--instrumentation-metadata-file=.scribble-arming.meta.json",
            "--debug-events",
            "--no-assert",
        ]
        + [f"{tmp_path}/{t}" for t in targets]
    )

    start_faas_campaign_mock.assert_called_once()
    payload = start_faas_campaign_mock.call_args[0][0]
    processed_payload = get_processed_payload(targets)
    corpus = processed_payload["corpus"]
    if corpus_target:
        corpus = {**corpus, "target": corpus_target}
    assert payload["parameters"] == processed_payload["parameters"]
    assert payload["corpus"] == corpus
    assert_is_equal(payload["contracts"], processed_payload["contracts"])
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"
    assert payload["quickCheck"] is True
