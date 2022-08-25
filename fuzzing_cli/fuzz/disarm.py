import logging
from typing import Optional

import click
from click import ClickException

from fuzzing_cli.fuzz.scribble import ScribbleMixin

LOGGER = logging.getLogger("fuzzing-cli")


@click.command("disarm")
@click.argument("targets", default=None, nargs=-1, required=False)
@click.option(
    "--scribble-path",
    type=click.Path(),
    default=None,
    help="Path to a custom scribble executable (beta)",
)
@click.pass_obj
def fuzz_disarm(ctx, targets, scribble_path: Optional[str]) -> None:
    """Revert the target files to their original, un-instrumented state.

    \f

    This will run :code:`scribble --disarm ...` on the given target files,
    reverting their code in-place to their original state using scribble.

    The following YAML context options are supported:
    - analyze
        - scribble-path

    :param ctx: The context, mainly used to get YAML params
    :param targets: Arguments passed to the `scribble`
    :param scribble_path: Optional path to the scribble executable
    """
    analyze_config = ctx.get("analyze", {}) or {}
    scribble_path = scribble_path or analyze_config.get("scribble-path") or "scribble"

    fuzz_config = ctx.get("fuzz", {}) or {}
    targets = targets or fuzz_config.get("targets") or None

    if not targets:
        raise click.exceptions.UsageError(
            "Target not provided. You need to provide a target as the last parameter of the `fuzz disarm` command."
            "\nYou can also set the `targets` on the `fuzz` key of your .fuzz.yml config file."
        )

    try:
        return_code, out, err = ScribbleMixin.disarm_solc_in_place(
            file_list=targets, scribble_path=scribble_path
        )
        if return_code == 0:
            click.secho(out)
        else:
            LOGGER.debug(f"code={return_code}, out={out}")
            raise ClickException(
                f"ScribbleError:\nThere was an error un-instrumenting your contracts with scribble:\n{err}"
            )
    except FileNotFoundError:
        raise click.exceptions.UsageError(
            f'Scribble not found at path "{scribble_path}". '
            f"Please provide scribble path using either `--scribble-path` option to `fuzz disarm` command"
            f"or set the `scribble-path` under the `analyze` key in your fuzzing config file"
        )
    except:
        raise
