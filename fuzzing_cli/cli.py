"""The main runtime of the Fuzzing CLI."""
import logging
import sys
from pathlib import Path

import click
import yaml

from fuzzing_cli import __version__
from fuzzing_cli.fuzz.arm import fuzz_arm
from fuzzing_cli.fuzz.disarm import fuzz_disarm
from fuzzing_cli.fuzz.run import fuzz_run

LOGGER = logging.getLogger("fuzzing-cli")
logging.basicConfig(level=logging.WARNING)


# noinspection PyIncorrectDocstring
@click.group()
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    envvar="FUZZING_DEBUG",
    help="Provide additional debug output",
)
@click.option(
    "-c",
    "--config",
    type=click.Path(exists=True),
    help="YAML config file for default parameters",
)
@click.option("--stdout", is_flag=True, default=False, help="Force printing to stdout")
@click.pass_context
def cli(ctx, debug: bool, config: str, stdout: bool) -> None:
    """Your CLI for interacting with https://fuzzing.diligence.tools

    \f

    :param ctx: Click context holding group-level parameters
    :param debug: Boolean to enable the `logging` debug mode
    :param config: YAML config file to read default parameters from
    :param stdout: Force printing to stdout and ignore output files
    """

    # set loggers to debug mode
    if debug:
        for name in logging.root.manager.loggerDict:
            logging.getLogger(name).setLevel(logging.DEBUG)

    ctx.obj = {"debug": debug, "config": config}

    LOGGER.debug("Initializing configuration context")
    config_file = config or ".fuzz.yml"
    if Path(config_file).is_file():
        LOGGER.debug(f"Parsing config at {config_file}")
        with open(config_file) as config_f:
            parsed_config = yaml.safe_load(config_f.read())
    else:
        parsed_config = {"fuzz": {}, "analyze": {}}

    # The analyze/fuzz context is updated separately in the command
    # implementation
    ctx.obj["analyze"] = parsed_config.get("analyze", {})
    ctx.obj["fuzz"] = parsed_config.get("fuzz", {})

    # overwrite context with top-level YAML config keys if necessary
    # update_context(ctx.obj, "ci", parsed_config, "ci", False)
    # if stdout:
    #     # if forced stdout, don't set output file
    #     ctx.obj["output"] = None
    # else:
    #     update_context(ctx.obj, "output", parsed_config, "output", None)
    # update_context(ctx.obj, "fmt", parsed_config, "format", "table")
    # update_context(ctx.obj, "yes", parsed_config, "confirm", False)
    # update_context(ctx.obj, "table_sort_key", parsed_config, "table-sort-key", "line")

    # set return value - used for CI failures
    ctx.obj["retval"] = 0

    LOGGER.debug(f"Initializing tool name middleware with {__version__}")


LOGGER.debug("Registering main commands")


LOGGER.debug("Registering fuzz commands")
cli.add_command(fuzz_run)
cli.add_command(fuzz_arm)
cli.add_command(fuzz_disarm)

if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
