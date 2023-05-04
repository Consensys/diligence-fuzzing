import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import click
import toml

from fuzzing_cli.fuzz.config import FuzzingOptions, omit_none
from fuzzing_cli.fuzz.ide import IDEArtifacts, IDERepository
from fuzzing_cli.fuzz.quickcheck_lib.quickcheck import prepare_seed_state
from fuzzing_cli.fuzz.run import submit_campaign

LOGGER = logging.getLogger("fuzzing-cli")


def parse_config() -> Dict[str, Any]:
    LOGGER.debug("Invoking `forge config` command")
    result = subprocess.run(["forge", "config"], check=True, stdout=subprocess.PIPE)
    LOGGER.debug("Invoking `forge config` command succeeded. Parsing config ...")
    LOGGER.debug(f"Raw forge config {result.stdout.decode()}")
    return toml.loads(result.stdout.decode())


def compile_tests(build_args):
    cmd = ["forge", "build", "--build-info", "--force", *build_args]
    LOGGER.debug(f"Invoking `forge build` command ({json.dumps(cmd)})")

    # we set the environment variables because passing a forge config
    # file as a parameter does not work unless we override the user's
    # config file. These env vars are cleared when the process ends.
    os.environ["FOUNDRY_OPTIMIZER"] = "false"
    os.environ["FOUNDRY_BYTECODE_HASH"] = "ipfs"
    os.environ["FOUNDRY_CBOR_METADATA"] = "true"

    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    LOGGER.debug("Invoking `forge build` command succeeded")


def collect_tests(
    test_dir: Path,
    match_path: Optional[str] = None,
    match_contract: Optional[str] = None,
) -> Tuple[List[str], Optional[Dict[str, Set[str]]], Dict[str, Dict[str, List[str]]]]:
    targets: List[str] = []
    target_contracts: Optional[Dict[str, Set[str]]] = None
    cmd = ["forge", "test", "--list", "--json"]
    if match_path is None and match_contract is None:
        cmd += ["--match-path", f"{test_dir}/*"]

    if match_path:
        cmd += ["--match-path", match_path]

    if match_contract:
        target_contracts = {}
        cmd += ["--match-contract", match_contract]
    LOGGER.debug(
        f"Invoking `forge test --list` command to list tests ({json.dumps(cmd)})"
    )
    result = subprocess.run(
        cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    LOGGER.debug(
        f"Invoking `forge test --list` command succeeded. Parsing the list ..."
    )
    LOGGER.debug(f"Raw tests list {result.stdout.decode()}")
    tests: Dict[str, Dict[str, List[str]]] = json.loads(
        result.stdout.decode().splitlines()[-1]
    )
    for test_path, test_contracts in tests.items():
        targets.append(test_path)
        if match_contract:
            target_contracts[test_path] = {
                contract for contract in test_contracts.keys()
            }
    return targets, target_contracts, tests


@click.group("forge")
def cli():  # pragma: no-cover
    """Submit foundry unit tests to fuzzing"""
    pass


@cli.command("test")
@click.option(
    "--key",
    "-k",
    type=click.STRING,
    help="API key, can be created on the FaaS Dashboard. ",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Outputs the data to be sent to the FaaS API without making the request.",
)
@click.option(
    "--match-contract",
    type=click.STRING,
    default=None,
    help="Only run tests in contracts matching the specified regex pattern",
)
@click.option(
    "--match-path",
    type=click.STRING,
    default=None,
    help="Only run tests in source files matching the specified glob pattern",
)
@click.option(
    "--build-args",
    default=None,
    help="Additional string of `forge compile` command arguments for custom build strategies ("
    "e.g. --build-args=--deny-warnings --build-args --use 0.8.1)",
)
def foundry_test(
    key: str,
    dry_run: bool,
    build_args: Optional[str],
    match_contract: Optional[str],
    match_path: Optional[str],
):
    """
    Command to:
     * Compile unit tests
     * Automatically collect unit-test contracts
     * Submit to fuzzing
    """
    click.echo("🛠️  Parsing foundry config")
    foundry_config = parse_config()

    click.echo("🛠️  Compiling tests")
    compile_tests([] if build_args is None else build_args.split(" "))

    click.echo("🛠️  Collecting tests")
    targets, target_contracts, tests_list = collect_tests(
        test_dir=Path(foundry_config["profile"]["default"]["test"]),
        match_path=match_path,
        match_contract=match_contract,
    )

    options = FuzzingOptions(
        ide="foundry",
        build_directory=foundry_config["profile"]["default"]["out"],
        sources_directory=foundry_config["profile"]["default"]["src"],
        targets=targets,
        quick_check=True,
        enable_cheat_codes=True,
        foundry_tests=True,
        target_contracts=target_contracts,
        foundry_tests_list=tests_list,
        dry_run=dry_run,
        smart_mode=False,
        **omit_none({"key": key}),
    )

    repo = IDERepository.get_instance()
    artifacts: IDEArtifacts = repo.get_ide("foundry")(
        options=options,
        targets=options.targets,
        build_dir=options.build_directory,
        sources_dir=options.sources_directory,
        map_to_original_source=False,
    )

    click.echo("🛠️  Collecting and validating campaigns for submission")
    artifacts.validate()

    click.echo("🛠️  Preparing the seed state")
    seed_state = prepare_seed_state(
        artifacts.contracts, options.number_of_cores, options.corpus_target
    )

    click.echo(f"⚡️ Submitting campaigns")
    submit_campaign(options, repo.get_ide("foundry").get_name(), artifacts, seed_state)

    return click.echo("Done 🎉")
