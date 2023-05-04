import click

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.lessons import FuzzingLessons
from fuzzing_cli.fuzz.rpc.rpc import RPCClient


def prepare_rpc_client() -> RPCClient:
    options = FuzzingOptions(
        no_build_directory=True,
        no_key=True,
        no_deployed_contract_address=True,
        smart_mode=False,
    )
    return RPCClient(options.rpc_url, options.number_of_cores)


@click.group("lesson")
def cli():
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
def start(description: str):
    """Start recording fuzzing lesson"""
    fl = FuzzingLessons()
    fl.start_lesson(description, prepare_rpc_client())
    click.secho(f'Started recording fuzzing lesson "{description}"')


# TODO: add "save" alias
@cli.command("stop")
def stop():
    """Stop recording fuzzing lesson and save results"""
    fl = FuzzingLessons()
    description = fl.stop_lesson(prepare_rpc_client())
    click.secho(
        f'Fuzzing lesson "{description}" recording '
        f"was stopped and results were saved to be used at a next campaign run"
    )


@cli.command("abort")
def abort():
    """Abort recording fuzzing lesson"""
    fl = FuzzingLessons()
    description = fl.abort_lesson()
    click.secho(f'Fuzzing lesson "{description}" recording was aborted')
