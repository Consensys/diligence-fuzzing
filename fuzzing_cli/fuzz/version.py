import click

from fuzzing_cli import __version__


@click.command("version")
def fuzz_version():
    """Show diligence-fuzzing version"""
    click.secho(f"v{__version__}")
