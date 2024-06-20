import json as jsonlib
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.analytics import Session
from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions


def prepare_config(tmp_path: Path, monkeypatch):
    os.chdir(tmp_path)
    monkeypatch.setenv("FUZZ_CONFIG_FILE", str(tmp_path / ".fuzz.yml"))

    (tmp_path / ".fuzz.yml").write_text(
        yaml.dump(
            {
                "fuzz": {
                    "ide": "hardhat",
                    "targets": ["contracts/ERC20.sol"],
                    "smart_mode": False,
                },
                "analyze": {
                    "no_assert": True,
                },
            }
        )
    )

    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "FUZZ_FOUNDRY_TESTS=true",
                "FUZZ_TIME_LIMIT=5m",
                "ANALYZE_SCRIBBLE_PATH=ext/scribble",
                "FUZZ_DEPLOYED_CONTRACT_ADDRESS=0x123",
                'FUZZ_ADDITIONAL_CONTRACTS_ADDRESSES=["0x456", "0x789"]',
            ]
        )
    )

    monkeypatch.setenv("FUZZ_CAMPAIGN_NAME_PREFIX", "test")
    monkeypatch.setenv("FUZZ_TIME_LIMIT", "20m")
    monkeypatch.setenv("ANALYZE_SCRIBBLE_PATH", "ext2/scribble")
    monkeypatch.setenv(
        "FUZZ_API_KEY", "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    )


def test_fuzzing_options_parsing(tmp_path, monkeypatch):
    prepare_config(tmp_path, monkeypatch)

    options = FuzzingOptions(
        build_directory="build",
    )

    assert options.foundry_tests is True
    assert options.time_limit == 1200
    assert options.campaign_name_prefix == "test"
    assert options.ide == "hardhat"
    assert options.targets == ["contracts/ERC20.sol"]
    assert options.key == "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"
    assert options.build_directory == Path.cwd().joinpath("build")
    assert options.sources_directory is None

    analyze_options = AnalyzeOptions(
        remappings=["a=b"],
    )

    assert analyze_options.scribble_path == "ext2/scribble"
    assert analyze_options.remappings == ["a=b"]
    assert analyze_options.no_assert is True
    assert analyze_options.solc_version is None


@pytest.mark.parametrize("json", [True, False])
@pytest.mark.parametrize("give_analytics_consent", [True, False])
def test_config_show(tmp_path, monkeypatch, json: bool, give_analytics_consent: bool):
    Session.give_consent(give_analytics_consent)

    prepare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("FUZZ_SOURCES_DIRECTORY", "contracts")
    monkeypatch.setenv("FUZZ_BUILD_DIRECTORY", "build")
    monkeypatch.setenv(
        "FUZZ_TARGETS", '["contracts/ERC20.sol", "contracts/ERC721.sol"]'
    )
    runner = CliRunner()
    cmd = ["config", "show"]
    if json:
        cmd += ["--json"]
    result = runner.invoke(cli, cmd)

    faas_options_json = {
        "ide": "hardhat",
        "build_directory": f"{tmp_path.joinpath('build')}",
        "sources_directory": f"{tmp_path.joinpath('contracts')}",
        "key": "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
        "project": None,
        "corpus_target": None,
        "number_of_cores": 1,
        "time_limit": 1200,
        "targets": [
            "contracts/ERC20.sol",
            "contracts/ERC721.sol",
        ],
        "deployed_contract_address": "0x123",
        "additional_contracts_addresses": ["0x456", "0x789"],
        "rpc_url": "http://localhost:8545",
        "campaign_name_prefix": "test",
        "map_to_original_source": False,
        "enable_cheat_codes": None,
        "chain_id": None,
        "max_sequence_length": None,
        "ignore_code_hash": None,
        "incremental": False,
        "truffle_executable_path": None,
        "quick_check": False,
        "foundry_tests": True,
        "target_contracts": None,
        "dry_run": False,
        "smart_mode": False,
        "include_library_contracts": False,
        "check_updates": False,
        "ci_mode": False,
    }

    analyze_options_json = {
        "solc_version": None,
        "remappings": [],
        "scribble_path": "ext2/scribble",
        "no_assert": True,
        "assert_": False,
    }

    product_analytics_options_json = {
        "report_crashes": True,
        "allow_analytics": give_analytics_consent,
    }

    fuzz_config_repr = "\n".join([f"{k} = {v}" for k, v in faas_options_json.items()])
    analyze_config_repr = "\n".join(
        [f"{k} = {v}" for k, v in analyze_options_json.items()]
    )
    product_analytics_config_repr = "\n".join(
        [f"{k} = {v}" for k, v in product_analytics_options_json.items()]
    )

    assert result.exit_code == 0
    if json:
        out = jsonlib.dumps(
            {
                "fuzz": faas_options_json,
                "analyze": analyze_options_json,
                "productAnalytics": product_analytics_options_json,
            }
        )
        assert result.output == f"{out}\n"
    else:
        assert (
            result.output == f"FUZZ CONFIG\n-----------\n{fuzz_config_repr}\n\n"
            f"ANALYZE CONFIG\n--------------\n{analyze_config_repr}\n\n"
            f"PRODUCT ANALYTICS\n--------------\n{product_analytics_config_repr}\n"
        )


@pytest.mark.parametrize("give_analytics_consent", [True, False])
def test_config_set_analytics_consent(
    tmp_path, monkeypatch, give_analytics_consent: bool
):
    Session.give_consent(give_analytics_consent)
    monkeypatch.setenv("FUZZ_SOURCES_DIRECTORY", "contracts")
    prepare_config(tmp_path, monkeypatch)
    runner = CliRunner()
    cmd = ["config", "set"]
    if give_analytics_consent:
        # disallow product analytics if the consent is previously given
        cmd += ["--no-product-analytics"]
        status = "disallowed"
    else:
        # else allow one if the consent was not given
        cmd += ["--product-analytics"]
        status = "allowed"
    result = runner.invoke(cli, cmd)

    assert result.exit_code == 0
    assert result.output == f"🛠️  Product analytics collection is now {status}\n"

    result = runner.invoke(cli, ["config", "show", "--json"])
    out = jsonlib.loads(result.output)
    assert out["productAnalytics"]["allow_analytics"] is not give_analytics_consent
