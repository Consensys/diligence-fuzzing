"""The main runtime of the MythX CLI."""
import logging
import sys
from pathlib import Path

import click
import yaml
from pythx import MythXAPIError

from mythx_cli import __version__

# DO NOT EDIT!! Breaks the app
from mythx_cli.formatter import FORMAT_RESOLVER
from mythx_cli.fuzz.arm import fuzz_arm
from mythx_cli.fuzz.disarm import fuzz_disarm
from mythx_cli.fuzz.run import fuzz_run

LOGGER = logging.getLogger("mythx-cli")
logging.basicConfig(level=logging.WARNING)


class APIErrorCatcherGroup(click.Group):
    """A custom click group to catch API-related errors.

    This custom Group implementation catches :code:`MythXAPIError`
    exceptions, which get raised when the API returns a non-200
    status code. It is used to notify the user about the error that
    happened instead of triggering an uncaught exception traceback.

    It is given to the main CLI entrypoint and propagated to all
    subcommands.
    """

    def __call__(self, *args, **kwargs):
        try:
            return self.main(*args, **kwargs)
        except MythXAPIError as exc:
            LOGGER.debug("Caught API error")
            click.echo("The API returned an error:\n{}".format(exc))
            sys.exit(1)


# noinspection PyIncorrectDocstring
@click.group(cls=APIErrorCatcherGroup)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    envvar="MYTHX_DEBUG",
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
    :param api_key: User JWT api token from the MythX dashboard
    :param username: The MythX account ETH address/username
    :param password: The account password from the MythX dashboard
    :param fmt: The formatter to use for the subcommand output
    :param ci: Boolean to return exit code 1 on medium/high-sev issues
    :param output: Output file to write the results into
    :param config: YAML config file to read default parameters from
    :param stdout: Force printing to stdout and ignore output files
    :param table_sort_key: The column to sort the default table output by
    """

    # set loggers to debug mode
    if debug:
        for name in logging.root.manager.loggerDict:
            logging.getLogger(name).setLevel(logging.DEBUG)

    ctx.obj = {"debug": debug, "config": config}

    LOGGER.debug("Initializing configuration context")
    config_file = config or ".mythx.yml"
    if Path(config_file).is_file():
        LOGGER.debug(f"Parsing config at {config_file}")
        with open(config_file) as config_f:
            parsed_config = yaml.safe_load(config_f.read())
    else:
        parsed_config = {"analyze": {}}

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
