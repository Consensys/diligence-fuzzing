import json
from pathlib import Path
from typing import List
from unittest.mock import patch, Mock

import pytest
import solcx
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.config.utils import parse_config
from fuzzing_cli.fuzz.faas import FaasClient
from tests.common import write_config, get_test_case
from tests.testdata.quickcheck_project.echidna.utils import get_compilation_artifacts, get_processed_payload


def test_fuzz_auto(tmp_path: Path, truffle_echidna_project, fake_process):
    fake_process.register_subprocess([fake_process.any()])

    with patch(
        "fuzzing_cli.fuzz.quickcheck.determine_ide",
    ) as determine_ide_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_targets",
    ) as determine_targets_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_cpu_cores",
    ) as determine_cpu_cores_mock, patch(
        "fuzzing_cli.fuzz.quickcheck.determine_campaign_name",
    ) as determine_campaign_name_mock:
        determine_ide_mock.return_value = truffle_echidna_project["ide"]
        determine_targets_mock.return_value = [f"{tmp_path}/contracts"]
        determine_cpu_cores_mock.return_value = 1
        determine_campaign_name_mock.return_value = "test-campaign"

        runner = CliRunner()
        result = runner.invoke(cli, ["auto"])

    assert result.exit_code == 0

    assert len(fake_process.calls) == 1
    assert fake_process.calls[0] == ["scribble-generate", "--targets", f"{tmp_path}/contracts"]

    config = parse_config(tmp_path.joinpath(f".fuzz_{tmp_path.name.lower().replace('-', '_')}.yml"))
    assert config["fuzz"].get("ide") == "truffle"
    assert list(config["fuzz"].get("targets")) == [
        f"{tmp_path}/contracts/SecondVulnerableTokenTest.sol",
        f"{tmp_path}/contracts/VulnerableTokenTest.sol",
    ]
    assert config["fuzz"].get("quick_check") == True
    assert config["fuzz"].get("number_of_cores") == 1
    assert config["fuzz"].get("campaign_name_prefix") == "test-campaign"
    assert config["analyze"].get("remappings") is None
    assert config["analyze"].get("solc-version") is None
    assert config["analyze"].get("scribble-path") == 'scribble'
    assert config["analyze"].get("no-assert") is None


@pytest.mark.parametrize(
    "targets",
    [
        ["contracts/VulnerableTokenTest.sol", "contracts/SecondVulnerableTokenTest.sol"],
        ["contracts/VulnerableTokenTest.sol"],
        ["contracts/SecondVulnerableTokenTest.sol"],
    ],
)
def test_fuzz_run(tmp_path: Path, truffle_echidna_project_armed, fake_process, targets: List[str]):
    write_config(
        base_path=str(tmp_path),
        **{
            **truffle_echidna_project_armed,
            "targets": targets,
        },
        quick_check=True,
    )

    fake_process.register_subprocess([fake_process.any()])

    with patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock, patch.object(
        FaasClient, "generate_campaign_name", new=Mock(return_value="test-campaign-1")
    ), patch.object(
        solcx, "compile_standard",
    ) as compile_standard_mock, patch.object(
        solcx, "get_installed_solc_versions",
    ) as get_installed_solc_versions_mock, patch.object(
        solcx, "install_solc",
    ) as install_solc_mock, patch.object(
        solcx, "set_solc_version",
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
    payload = start_faas_campaign_mock.call_args[0][0]

    set_solc_version_mock.assert_called_once_with("v0.8.1", silent=True)

    _sources = {
        f"{tmp_path}/{t}": {"urls": [f"{tmp_path}/{t}"]}
        for t in targets
    }
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
    assert fake_process.calls[0] == ([
        "scribble",
        "--arm",
        "--output-mode=files",
        "--instrumentation-metadata-file=.scribble-arming.meta.json",
    ] + [f"{tmp_path}/{t}" for t in targets])

    start_faas_campaign_mock.assert_called_once()
    payload = start_faas_campaign_mock.call_args[0][0]
    processed_payload = get_processed_payload(targets)
    assert payload["parameters"] == processed_payload["parameters"]
    # assert payload["corpus"] == processed_payload["corpus"]
    assert payload["contracts"] == processed_payload["contracts"]
    assert payload["sources"] == processed_payload["sources"]
    assert payload["name"] == "test-campaign-1"
    assert payload["quickCheck"] is True
