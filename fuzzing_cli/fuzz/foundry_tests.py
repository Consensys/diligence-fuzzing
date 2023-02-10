import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import toml
from click import Context

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.ide import IDEArtifacts, IDERepository
from fuzzing_cli.fuzz.quickcheck_lib.quickcheck import prepare_seed_state
from fuzzing_cli.fuzz.run import submit_campaign
from fuzzing_cli.util import files_by_directory


def parse_config() -> Dict[str, Any]:
    result = subprocess.run(["forge", "config"], check=True, stdout=subprocess.PIPE)
    return toml.loads(result.stdout.decode())


def compile_tests(build_args):
    cmd = ["forge", "build", "--build-info", "--force", *build_args]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def collect_tests(test_dir: Path):
    test_contracts: List[str] = files_by_directory(str(test_dir), ".t.sol")
    return test_contracts


@click.group("forge")
@click.pass_obj
def cli(ctx):  # pragma: no-cover
    """Submit foundry unit tests to fuzzing"""
    pass


# TODO: allow forge build parameters
@cli.command("test")
@click.option(
    "--key",
    "-k",
    type=click.STRING,
    required=True,
    help="API key, can be created on the FaaS Dashboard. ",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Outputs the data to be sent to the FaaS API without making the request.",
)
@click.option(
    "--build-args",
    default=None,
    help="Additional string of `forge compile` command arguments for custom build strategies ("
    "e.g. --build-args=--deny-warnings --build-args --use 0.8.1)",
)
@click.pass_context
def foundry_test(ctx: Context, key: str, dry_run: bool, build_args: Optional[str]):
    """
    Command to:
     * Compile unit tests
     * Automatically collect unit-test contracts
     * Submit to fuzzing
    """
    fuzz_config = ctx.obj.get("fuzz", {}) or {}
    foundry_config = parse_config()
    compile_tests([] if build_args is None else build_args.split(" "))
    targets = collect_tests(Path(foundry_config["profile"]["default"]["test"]))

    options = FuzzingOptions.from_config(
        fuzz_config,
        ide="foundry",
        build_directory=foundry_config["profile"]["default"]["out"],
        sources_directory=foundry_config["profile"]["default"]["src"],
        targets=targets,
        key=key,
        quick_check=True,
        enable_cheat_codes=True,
        dry_run=dry_run,
    )

    repo = IDERepository.get_instance()
    artifacts: IDEArtifacts = repo.get_ide("foundry")(
        options=options,
        targets=options.target,
        build_dir=options.build_directory,
        sources_dir=options.sources_directory,
        map_to_original_source=False,
    )
    artifacts.validate()

    seed_state = prepare_seed_state(
        artifacts.contracts, options.number_of_cores, options.corpus_target
    )

    return submit_campaign(
        options, repo.get_ide("foundry").get_name(), artifacts, seed_state
    )
