import random
import string
from pathlib import Path
from typing import List, Optional

import click
from click import UsageError, style

from fuzzing_cli.fuzz.config import generate_yaml
from fuzzing_cli.fuzz.config.generate import (
    determine_campaign_name,
    determine_cpu_cores,
    determine_ide,
    determine_targets,
)
from fuzzing_cli.fuzz.quickcheck_lib import annotate_contracts


def create_config(
    config_name: str,
    ide: str,
    targets: List[str],
    number_of_cores: int,
    campaign_name_prefix: str,
    remappings: Optional[List[str]] = None,
    solc_version: Optional[str] = None,
    scribble_path: Optional[str] = None,
    no_assert: Optional[bool] = None,
) -> Path:
    config_path = Path().cwd().joinpath(config_name)
    with config_path.open("w") as f:
        f.write(
            generate_yaml(
                {
                    "ide": ide,
                    "build_directory": None,
                    "sources_directory": None,
                    "targets": targets,
                    "rpc_url": None,
                    "number_of_cores": number_of_cores,
                    "campaign_name_prefix": campaign_name_prefix,
                    "no-assert": True,
                    "quick_check": True,
                    "remappings": remappings,
                    "solc_version": solc_version,
                    "scribble_path": scribble_path,
                    "no_assert": no_assert,
                }
            )
        )
        f.flush()
    return config_path


def generate_config_name(suffix: Optional[str] = None, randomize_name=False):
    if not suffix:
        suffix = Path.cwd().name.lower().replace("-", "_")
    if randomize_name:
        suffix += f"_{''.join(random.choice(string.ascii_lowercase) for _ in range(3))}"
    return f".fuzz_{suffix}.yml"


@click.command("auto")
@click.option(
    "--individual",
    help="Option to create separate fuzzing configs for each auto-annotated test contract",
    is_flag=True,
    default=False,
)
@click.option("--config-file", type=click.Path(), default=None)
@click.option(
    "--scribble-path",
    type=click.STRING,
    default="scribble",
    help="Path to a custom scribble executable",
)
@click.option(
    "--scribble-generator-path",
    type=click.STRING,
    default="scribble-generate",
    required=False,
    help="Path to a custom scribble-generator executable",
)
@click.option(
    "--remap-import",
    type=click.STRING,
    multiple=True,
    help="Add a solc compilation import remapping (space separated)",
    default=None,
)
@click.option(
    "--solc-version",
    type=click.STRING,
    help="The solc version to use for compilation",
    default=None,
)
@click.option(
    "--no-assert",
    is_flag=True,
    default=False,
    required=False,
    help="If specified execution will not halt when an invariant is violated (only an event will be emitted).",
)
@click.pass_obj
def fuzz_auto(
    ctx,
    individual: bool,
    config_file: Optional[str],
    scribble_path: str,
    scribble_generator_path: str,
    remap_import: List[str],
    solc_version: Optional[str],
    no_assert: bool,
) -> None:
    """
    Automatically annotate test contracts
    """
    ide = determine_ide()
    targets = determine_targets(ide)
    number_of_cores = determine_cpu_cores()
    campaign_name_prefix = determine_campaign_name()

    annotated_targets = annotate_contracts(targets, scribble_generator_path)

    if not annotated_targets:
        raise UsageError("No target contains `echidna` or `ds-test` test cases")

    targets_list_output = [
        f"  🛠  {style(target, fg='yellow', italic=True)}"
        for target in annotated_targets
    ]
    targets_list_output_string = "\n".join(targets_list_output)
    click.echo(
        f"\n🛠  Here's the list of instrumented contracts:\n  {targets_list_output_string}"
    )

    if individual:
        for target in annotated_targets:
            config_path = create_config(
                config_name=generate_config_name(config_file or Path(target).name),
                ide=ide,
                targets=[str(target)],
                number_of_cores=number_of_cores,
                campaign_name_prefix=f"{campaign_name_prefix}_{''.join(random.choice(string.ascii_lowercase) for _ in range(3))}",
                remappings=remap_import,
                solc_version=solc_version,
                scribble_path=scribble_path,
                no_assert=no_assert,
            )
            st = style(target, fg="yellow", italic=True)
            scp = style(config_path, fg="yellow", italic=True)
            click.echo(f"⚡️ Generating configs at {scp} for {st}")
    else:
        config_path = create_config(
            config_name=generate_config_name(),
            ide=ide,
            targets=[str(t) for t in annotated_targets],
            number_of_cores=number_of_cores,
            campaign_name_prefix=campaign_name_prefix,
            remappings=remap_import,
            solc_version=solc_version,
            scribble_path=scribble_path,
            no_assert=no_assert,
        )

        click.echo(
            f"⚡️ Alright! Generating config at {style(config_path, fg='yellow', italic=True)}"
        )

    click.echo("Done 🎉")
