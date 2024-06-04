import logging
from pathlib import Path
from typing import Optional

import click
from click import ClickException

from fuzzing_cli.fuzz.analytics import trace
from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions, omit_none
from fuzzing_cli.fuzz.exceptions import ScribbleError
from fuzzing_cli.fuzz.scribble import ScribbleMixin

LOGGER = logging.getLogger("fuzzing-cli")


@click.command("disarm")
@click.argument("targets", default=None, nargs=-1, required=False)
@click.option(
    "--scribble-path",
    type=click.Path(),
    default=None,
    help="Path to a custom scribble executable",
)
@trace("fuzz_disarm")
def fuzz_disarm(targets, scribble_path: Optional[str]) -> None:
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

    options = AnalyzeOptions(
        **omit_none(
            {
                "scribble_path": scribble_path,
            }
        ),
    )

    fuzzing_options = FuzzingOptions(
        **omit_none(
            {
                "targets": targets if len(targets) > 0 else None,
            }
        ),
        # TODO: refactor this workaround for some config options validation
        ci_mode=True,
        no_build_directory=True,
        no_key=True,
        no_deployed_contract_address=True,
        smart_mode=False,
    )

    try:
        return_code, out, err = ScribbleMixin.disarm_solc_in_place(
            file_list=[Path(t) for t in fuzzing_options.targets],
            scribble_path=options.scribble_path,
        )
        if return_code == 0:
            click.secho(out)
        else:
            LOGGER.debug(f"code={return_code}, out={out}")
            raise ClickException(
                f"ScribbleError:\nThere was an error un-instrumenting your contracts with scribble:\n{err}"
            )
    except ClickException:
        raise
    except Exception as e:
        raise ScribbleError(e)
