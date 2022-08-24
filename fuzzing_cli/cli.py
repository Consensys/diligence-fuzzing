"""The main runtime of the Fuzzing CLI."""
import logging
import os
import sys
from pathlib import Path

import click
import yaml

from fuzzing_cli import __version__
from fuzzing_cli.fuzz.arm import fuzz_arm
from fuzzing_cli.fuzz.disarm import fuzz_disarm
from fuzzing_cli.fuzz.fuzzing_lessons import cli as fuzz_lesson
from fuzzing_cli.fuzz.generate_config import fuzz_generate_config
from fuzzing_cli.fuzz.quickcheck import fuzz_auto
from fuzzing_cli.fuzz.run import fuzz_run

LOGGER = logging.getLogger("fuzzing-cli")
LOGLEVEL = os.environ.get("LOGLEVEL", "WARNING").upper()
logging.basicConfig(level=LOGLEVEL)


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
    type=click.Path(),
    help="YAML config file for default parameters",
    default=".fuzz.yml",
)
@click.pass_context
def cli(ctx, debug: bool, config: str) -> None:
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

    LOGGER.debug("Initializing configuration context")
    if Path(config).is_file():
        LOGGER.debug(f"Parsing config at {config}")
        with open(config) as config_f:
            parsed_config = yaml.safe_load(config_f.read())
    else:
        parsed_config = {"fuzz": {}, "analyze": {}}

    ctx.obj = {
        "debug": debug,
        "config": str(Path(config).absolute()),
        "analyze": parsed_config.get("analyze", {}),
        "fuzz": parsed_config.get("fuzz", {}),
    }

    LOGGER.debug(f"Initializing tool name middleware with {__version__}")


LOGGER.debug("Registering main commands")


LOGGER.debug("Registering fuzz commands")
cli.add_command(fuzz_run)
cli.add_command(fuzz_arm)
cli.add_command(fuzz_disarm)
cli.add_command(fuzz_generate_config)
cli.add_command(fuzz_auto)
cli.add_command(fuzz_lesson)

if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
