import logging
from typing import Tuple

import click
from click import ClickException

from fuzzing_cli.fuzz.scribble import ScribbleMixin

LOGGER = logging.getLogger("fuzzing-cli")


@click.command("arm")
@click.argument("targets", default=None, nargs=-1, required=False)
@click.option(
    "--scribble-path",
    type=click.Path(),
    default=None,
    help="Path to a custom scribble executable (beta)",
)
@click.option(
    "--remap-import",
    type=click.STRING,
    multiple=True,
    help="Add a solc compilation import remapping "
    "(e.g. --remap-import <dep1>:<dep1_path> --remap-import <dep2>:<dep2_path>)",
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
def fuzz_arm(
    ctx,
    targets,
    scribble_path: str,
    remap_import: Tuple[str],
    solc_version: str,
    no_assert: bool,
) -> None:
    """Prepare the target files for Diligence Fuzzing API submission.

    \f

    This will run :code:`scribble --arm ...` on the given target files,
    instrumenting their code in-place with scribble. Additionally,
    solc parameters can be passed to get compilation to work.

    The following YAML context options are supported:
    - analyze
    - targets
    - scribble-path
    - remappings
    - solc

    :param ctx: The context, mainly used to get YAML params
    :param targets: Arguments passed to the `analyze` subcommand
    :param scribble_path: Optional path to the scribble executable
    :param remap_import: List of import remappings to pass on to solc
    :param solc_version: The solc version to use for Solidity compilation
    :param no_assert: If set execution will not halt when an invariant is violated (only an event will be emitted)
    """
    analyze_config = ctx.get("analyze", {}) or {}
    solc_version = solc_version or analyze_config.get("solc-version") or None
    remap_import = remap_import or analyze_config.get("remappings") or []
    scribble_path = scribble_path or analyze_config.get("scribble-path") or "scribble"
    no_assert = no_assert or analyze_config.get("no-assert") or False

    fuzz_config = ctx.get("fuzz", {}) or {}
    targets = targets or fuzz_config.get("targets") or None

    if not targets:
        raise click.exceptions.UsageError(
            "Target not provided. You need to provide a target as the last parameter of the `fuzz arm` command."
            "\nYou can also set the `targets` on the `fuzz` key of your .fuzz.yml config file."
        )

    try:
        return_code, out, err = ScribbleMixin.instrument_solc_in_place(
            file_list=targets,
            scribble_path=scribble_path,
            remappings=remap_import,
            solc_version=solc_version,
            no_assert=no_assert,
        )
        if return_code == 0:
            click.secho(out)
        else:
            LOGGER.debug(f"code={return_code}, out={out}")
            raise ClickException(
                f"ScribbleError:\nThere was an error instrumenting your contracts with scribble:\n{err}"
            )
    except FileNotFoundError:
        raise click.exceptions.UsageError(
            f'Scribble not found at path "{scribble_path}". '
            f"Please provide scribble path using either `--scribble-path` option to `fuzz arm` command"
            f"or set the `scribble-path` under the `analyze` key in your fuzzing config file"
        )
    except:
        raise
