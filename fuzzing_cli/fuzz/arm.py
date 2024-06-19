import logging
from pathlib import Path
from typing import List, Optional, Tuple

import click
from click import ClickException, style

from fuzzing_cli.fuzz.analytics import trace
from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions, omit_none
from fuzzing_cli.fuzz.exceptions import ScribbleError
from fuzzing_cli.fuzz.scribble import ScribbleMixin
from fuzzing_cli.fuzz.utils import detect_ide
from fuzzing_cli.util import sol_files_by_directory

LOGGER = logging.getLogger("fuzzing-cli")

QM = f"[{style('?', fg='yellow')}]"


def handle_validation_errors(
    targets: List[str],
    fuzzing_options: FuzzingOptions,
    prompt: bool = True,
    smart_mode: bool = False,
) -> List[Path]:
    if len(targets) > 0:
        return [Path(t) for t in targets]

    _IDEClass = detect_ide(fuzzing_options)
    suggested_targets = sorted(
        sol_files_by_directory(_IDEClass.get_default_sources_dir())
    )

    data = "\n".join([f"  ◦ {file_name}" for file_name in suggested_targets])
    error_message = f"⚠️ Targets were not provided but the following files can be set as targets to be armed:\n{data}"
    if smart_mode or (
        prompt
        and click.confirm(f"{QM} {error_message}\nAdd them to targets?", default=True)
    ):
        return suggested_targets
    click.secho(error_message)
    return [Path(t) for t in targets]


@click.command("arm")
@click.argument("targets", default=None, nargs=-1, required=False)
@click.option(
    "--scribble-path",
    type=click.Path(),
    default=None,
    help="Path to a custom scribble executable",
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
@trace("fuzz_arm")
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

    # allow no_targets for smart mode or prompts to run
    fuzzing_options = FuzzingOptions(
        # omit_none for targets to look in the config if the one was not provided as arg to fuzz arm command
        **omit_none({"targets": targets if len(targets) > 0 else None}),
        no_key=True,
        no_targets=True,
        no_deployed_contract_address=True,
    )
    _targets = handle_validation_errors(
        fuzzing_options.targets,
        fuzzing_options,
        prompt=not fuzzing_options.ci_mode,
        smart_mode=fuzzing_options.smart_mode,
    )

    try:
        return_code, out, err = ScribbleMixin.instrument_solc_in_place(
            file_list=_targets,
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
    except ClickException:
        raise
    except Exception as e:
        raise ScribbleError(e)
