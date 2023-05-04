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
from fuzzing_cli.fuzz.foundry_tests import cli as foundry_test
from fuzzing_cli.fuzz.fuzz_config import cli as fuzz_config
from fuzzing_cli.fuzz.fuzzing_lessons import cli as fuzz_lesson
from fuzzing_cli.fuzz.quickcheck import fuzz_auto
from fuzzing_cli.fuzz.run import fuzz_run
from fuzzing_cli.fuzz.version import fuzz_version

LOGGER = logging.getLogger("fuzzing-cli")


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
    """

    # set loggers to debug mode
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        for name in logging.root.manager.loggerDict:
            logging.getLogger(name).setLevel(logging.DEBUG)

    LOGGER.debug("Initializing configuration context")
    if Path(config).is_file():
        # this env var is used by the `FuzzingOptions` class to load the config later
        os.environ["FUZZ_CONFIG_FILE"] = str(Path(config).absolute())

        LOGGER.debug(f"Parsing config at {config}")
        with open(config) as config_f:
            parsed_config = yaml.safe_load(config_f.read())
    else:
        parsed_config = {"analyze": {}}

    ctx.obj = {
        "debug": debug,
        "config": str(Path(config).absolute()),
        "analyze": parsed_config.get("analyze", {}),
    }

    LOGGER.debug(f"Initializing tool name middleware with {__version__}")


LOGGER.debug("Registering main commands")


LOGGER.debug("Registering fuzz commands")
cli.add_command(fuzz_run)
cli.add_command(fuzz_arm)
cli.add_command(fuzz_disarm)
cli.add_command(fuzz_auto)
cli.add_command(fuzz_lesson)
cli.add_command(fuzz_version)
cli.add_command(foundry_test)
cli.add_command(fuzz_config)

if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
