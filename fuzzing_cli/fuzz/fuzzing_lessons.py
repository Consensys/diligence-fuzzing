from pathlib import Path
from typing import Dict

import click

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.lessons import FuzzingLessons
from fuzzing_cli.fuzz.rpc import RPCClient


def prepare_rpc_client(ctx: Dict[str, any]) -> RPCClient:
    fuzz_config = ctx.get("fuzz")
    options = FuzzingOptions.parse_obj(fuzz_config)
    return RPCClient(options.rpc_url, options.number_of_cores)


@click.group("lesson")
@click.pass_obj
def cli(ctx):
    pass


@cli.command("start")
@click.option(
    "-d",
    "--description",
    type=click.STRING,
    help="Fuzzing lesson description",
    default="",
)
@click.pass_obj
def start(ctx, description: str):
    config_path = Path(ctx.get("config"))
    if not config_path.absolute():
        config_path = Path.cwd().joinpath(Path(ctx.get("config")))
    FuzzingLessons.start_lesson(description, config_path, prepare_rpc_client(ctx))


# TODO: add "save" alias
@cli.command("stop")
@click.pass_obj
def stop(ctx):
    FuzzingLessons.stop_lesson(prepare_rpc_client(ctx))


@cli.command("abort")
def abort():
    FuzzingLessons.abort_lesson()

