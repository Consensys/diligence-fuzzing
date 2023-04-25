import os
from pathlib import Path

import yaml

from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions


def test_fuzzing_options_parsing(tmp_path, monkeypatch):
    os.chdir(tmp_path)
    monkeypatch.setenv("FUZZ_CONFIG_FILE", str(tmp_path / ".fuzz.yml"))

    (tmp_path / ".fuzz.yml").write_text(
        yaml.dump(
            {
                "fuzz": {
                    "ide": "hardhat",
                    "targets": ["contracts/ERC20.sol"],
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
            ]
        )
    )

    os.environ["FUZZ_CAMPAIGN_NAME_PREFIX"] = "test"
    os.environ["FUZZ_TIME_LIMIT"] = "20m"
    os.environ["ANALYZE_SCRIBBLE_PATH"] = "ext2/scribble"
    os.environ["FUZZ_API_KEY"] = "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"

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
