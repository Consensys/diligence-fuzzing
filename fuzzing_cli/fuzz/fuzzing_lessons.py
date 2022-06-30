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
    """Manage fuzzing lessons"""
    pass


@cli.command("start")
@click.option(
    "-d",
    "--description",
    type=click.STRING,
    help="Fuzzing lesson description",
    default="my lesson",
)
@click.pass_obj
def start(ctx, description: str):
    """Start recording fuzzing lesson"""
    config_path = Path(ctx.get("config"))
    if not config_path.absolute():
        config_path = Path.cwd().joinpath(Path(ctx.get("config")))
    FuzzingLessons.start_lesson(description, config_path, prepare_rpc_client(ctx))
    click.secho(f'Started recording fuzzing lesson "{description}"')


# TODO: add "save" alias
@cli.command("stop")
@click.pass_obj
def stop(ctx):
    """Stop recording fuzzing lesson and save results"""
    description = FuzzingLessons.stop_lesson(prepare_rpc_client(ctx))
    click.secho(
        f'Fuzzing lesson "{description}" recording '
        f"was stopped and results were saved to be used at a next campaign run"
    )


@cli.command("abort")
def abort():
    """Abort recording fuzzing lesson"""
    description = FuzzingLessons.abort_lesson()
    click.secho(f'Fuzzing lesson "{description}" recording was aborted')
