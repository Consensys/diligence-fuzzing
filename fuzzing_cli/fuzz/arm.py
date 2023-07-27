import logging
from typing import Optional, Tuple

import click
from click import ClickException

from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions, omit_none
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
    "--assert",
    "-a",
    "_assert",
    is_flag=True,
    default=None,
    required=False,
    help="If specified, execution will halt when an invariant is violated (instead of only emitting an event).",
)
def fuzz_arm(
    targets,
    scribble_path: str,
    remap_import: Tuple[str],
    solc_version: str,
    _assert: Optional[bool],
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
    :param _assert: If set, execution will halt when an invariant is violated
    """
    options = AnalyzeOptions(
        **omit_none(
            {
                "solc_version": solc_version,
                "remappings": remap_import if len(remap_import) > 0 else None,
                "scribble_path": scribble_path,
                "assert_": _assert,
            }
        )
    )

    fuzzing_options = FuzzingOptions(
        **omit_none(
            {
                "targets": targets if len(targets) > 0 else None,
            }
        ),
        no_build_directory=True,
        no_key=True,
        no_deployed_contract_address=True,
        smart_mode=False,
    )

    try:
        return_code, out, err = ScribbleMixin.instrument_solc_in_place(
            file_list=fuzzing_options.targets,
            scribble_path=options.scribble_path,
            remappings=options.remappings,
            solc_version=options.solc_version,
            no_assert=not options.assert_,
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
            f'Scribble not found at path "{options.scribble_path}". '
            f"Please provide scribble path using either `--scribble-path` option to `fuzz arm` command "
            f"or set one in config"
        )
    except:
        raise
