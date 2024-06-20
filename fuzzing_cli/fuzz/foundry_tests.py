import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import click
import toml

from fuzzing_cli.fuzz.analytics import Session, trace
from fuzzing_cli.fuzz.config import AuthHandler, FuzzingOptions, omit_none
from fuzzing_cli.fuzz.exceptions import (
    ForgeCollectTestsError,
    ForgeCompilationError,
    ForgeConfigError,
    ForgeNoTestsFoundError,
    ForgeNotFoundryDirectory,
)
from fuzzing_cli.fuzz.ide import FoundryArtifacts, IDERepository
from fuzzing_cli.fuzz.quickcheck_lib.quickcheck import (
    prepare_seed_state as prepare_seed_state_base,
)
from fuzzing_cli.fuzz.run import submit_campaign
from fuzzing_cli.util import executable_command

LOGGER = logging.getLogger("fuzzing-cli")


def prepare_seed_state(
    artifacts: FoundryArtifacts,
    number_of_cores: int,
    corpus_target: Optional[str] = None,
) -> Dict[str, Any]:
    # this method adds the `appendSetUpTx` flag to the seed state's steps based on whether the contract
    # has a setup method or not. For regular campaigns, this flag is omitted
    seed_state = prepare_seed_state_base(
        artifacts.contracts, number_of_cores, corpus_target
    )
    for i, contract in enumerate(artifacts.contracts):
        seed_state["analysis-setup"]["steps"][i][
            "appendSetUpTx"
        ] = artifacts.has_setup_method(contract)
    return seed_state


def parse_config() -> Dict[str, Any]:
    LOGGER.debug("Invoking `forge config` command")
    try:
        result = subprocess.run(
            [*executable_command("forge"), "config"],
            check=True,
            stdout=subprocess.PIPE,
        )
    except Exception as e:
        raise ForgeConfigError(e)
    LOGGER.debug("Invoking `forge config` command succeeded. Parsing config ...")
    LOGGER.debug(f"Raw forge config {result.stdout.decode()}")
    return toml.loads(result.stdout.decode())


def run_build_command(cmd):
    return subprocess.run(
        cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )


def compile_tests(build_args):
    cmd = [
        *executable_command("forge"),
        "build",
        "--build-info",
        "--force",
        *build_args,
    ]
    LOGGER.debug(f"Invoking `forge build` command ({json.dumps(cmd)})")

    # we set the environment variables because passing a forge config
    # file as a parameter does not work unless we override the user's
    # config file. These env vars are cleared when the process ends.
    os.environ["FOUNDRY_OPTIMIZER"] = "false"
    os.environ["FOUNDRY_BYTECODE_HASH"] = "ipfs"
    os.environ["FOUNDRY_CBOR_METADATA"] = "true"

    try:
        run_build_command(cmd)
    except Exception as e:
        # Here we try to compile with FOUNDRY_OPTIMIZER=true. This is because of a solidity bug where it sometimes fails to compile with FOUNDRY_OPTIMIZER=false.
        # More at https://github.com/ethereum/solidity/issues/12980#issuecomment-1562813429
        LOGGER.warning(
            "⚠️ Compilation failed with FOUNDRY_OPTIMIZER=false. Retrying with FOUNDRY_OPTIMIZER=true. This may result in lower quality results for the fuzzing campaign because compiler optimization affects source maps."
        )
        try:
            os.environ["FOUNDRY_OPTIMIZER"] = "true"
            os.environ["FOUNDRY_BYTECODE_HASH"] = "ipfs"
            os.environ["FOUNDRY_CBOR_METADATA"] = "true"
            run_build_command(cmd)
        except Exception as e:
            raise ForgeCompilationError(e)
    LOGGER.debug("Invoking `forge build` command succeeded")


def collect_tests(
    match_path: Optional[str] = None,
    match_contract: Optional[str] = None,
) -> Tuple[List[str], Optional[Dict[str, Set[str]]], Dict[str, Dict[str, List[str]]]]:
    targets: List[str] = []
    target_contracts: Optional[Dict[str, Set[str]]] = None
    cmd = [*executable_command("forge"), "test", "--list", "--json"]

    if match_path:
        cmd += ["--match-path", match_path]

    if match_contract:
        target_contracts = {}
        cmd += ["--match-contract", match_contract]
    LOGGER.debug(
        f"Invoking `forge test --list` command to list tests ({json.dumps(cmd)})"
    )
    try:
        result = subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
    except Exception as e:
        raise ForgeCollectTestsError(e)
    LOGGER.debug(
        f"Invoking `forge test --list --json` command succeeded. Parsing the list ..."
    )
    try:
        LOGGER.debug(f"Raw tests list {result.stdout.decode()}")
        tests: Dict[str, Dict[str, List[str]]] = json.loads(
            result.stdout.decode().splitlines()[-1]
        )
    # we catch the exception json.decoder.JSONDecodeError
    except json.decoder.JSONDecodeError as e:
        # we look at all the files in the current folder
        files = os.listdir(".")
        # and check if there is a foundry.toml file
        if not "foundry.toml" in files:
            raise ForgeNotFoundryDirectory()
        # if its a foundry directory, we return the error of tests not found.
        else:
            raise ForgeNoTestsFoundError()

    # if there are no tests, we return an empty list and throw an error
    if not tests:
        raise ForgeNoTestsFoundError()
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
    help="API key, it is **required** and can be created on the FaaS Dashboard. Learn more at https://fuzzing-docs.diligence.tools/getting-started/configuring-the-cli#subscriptions-and-api-key .\n",
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
@trace("fuzz_foundry_test", upload_session=True)
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

    # depending on the FOUNDRY_PROFILE env var, the profile name may be different,
    # and it will be the only key in the profile dict, so we need to get the first key
    profile_name = list(foundry_config["profile"].keys())[0]

    click.echo("🛠️  Compiling tests")
    compile_tests([] if build_args is None else build_args.split(" "))

    click.echo("🛠️  Collecting tests")

    targets, target_contracts, tests_list = collect_tests(
        match_path=match_path,
        match_contract=match_contract,
    )

    options = FuzzingOptions(
        ide="foundry",
        build_directory=foundry_config["profile"][profile_name]["out"],
        sources_directory=foundry_config["profile"][profile_name]["src"],
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
    auth_handler = AuthHandler(options)

    Session.set_local_context(
        ci_mode=options.ci_mode,
        user_id=auth_handler.user_id,
        rpc_node_kind="",
        rpc_node_version="",
    )

    repo = IDERepository.get_instance()
    artifacts = cast(
        FoundryArtifacts,
        repo.get_ide("foundry")(
            options=options,
            targets=options.targets,
            build_dir=options.build_directory,
            sources_dir=options.sources_directory,
            map_to_original_source=False,
        ),
    )

    click.echo("🛠️  Collecting and validating campaigns for submission")
    artifacts.validate()

    click.echo("🛠️  Preparing the seed state")
    seed_state = prepare_seed_state(
        artifacts, options.number_of_cores, options.corpus_target
    )

    click.echo(f"⚡️ Submitting campaigns")
    submit_campaign(
        options, repo.get_ide("foundry").get_name(), artifacts, seed_state, auth_handler
    )

    return click.echo("Done 🎉")
