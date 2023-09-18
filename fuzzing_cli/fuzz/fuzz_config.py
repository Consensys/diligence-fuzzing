import json as jsonlib
from pathlib import Path

import click
from click import style

from fuzzing_cli.fuzz.analytics import Session, trace
from fuzzing_cli.fuzz.config import AnalyzeOptions, FuzzingOptions
from fuzzing_cli.fuzz.config.generate import recreate_config, sync_config


@click.group("config")
def cli():  # pragma: no-cover
    """Manage diligence-fuzzing configuration"""
    pass


@cli.command("set")
@click.option(
    "--product-analytics/--no-product-analytics",
    is_flag=True,
    help="Allow product analytics collection",
    default=True,
)
@trace("fuzz_config_set")
def config_set(product_analytics: bool = True):
    """Allow or disallow product analytics collection. Result is saved in the app config file which is
    global for all projects."""
    Session.give_consent(product_analytics)
    click.echo(
        f"🛠️  Product analytics collection is now "
        f"{'allowed' if product_analytics else 'disallowed'}"
    )


@cli.command("show")
@click.option("--json", is_flag=True, help="Show configuration as JSON")
@trace("fuzz_config_show")
def show_config(json: bool = False):
    """Show current configuration (collected from yaml file, .env file, environment variables).
    Validation for required parameters is not performed."""
    options = FuzzingOptions(
        no_targets=True,
        no_build_directory=True,
        no_key=True,
        no_deployed_contract_address=True,
    )
    analyze_options = AnalyzeOptions()
    analytics_consents = Session.get_consents_status()
    if json:
        # here we get json string from the options (call .json()) because Pydantic should do the serialization
        # on complex types (like Path, datetime, etc.) first, so we could later use json.loads() to get a dict which
        # we can then serialize to json
        rep = jsonlib.dumps(
            {
                "fuzz": jsonlib.loads(options.json()),
                "analyze": jsonlib.loads(analyze_options.json()),
                "productAnalytics": analytics_consents,
            }
        )
    else:
        rep_fuzz = "\n".join([f"{k} = {v}" for k, v in options.dict().items()])
        rep_analyze = "\n".join(
            [f"{k} = {v}" for k, v in analyze_options.dict().items()]
        )
        rep_analytics = "\n".join([f"{k} = {v}" for k, v in analytics_consents.items()])
        rep = (
            f"FUZZ CONFIG\n{'-' * 11}\n{rep_fuzz}\n\n"
            f"ANALYZE CONFIG\n{'-' * 14}\n{rep_analyze}\n\n"
            f"PRODUCT ANALYTICS\n{'-' * 14}\n{rep_analytics}"
        )
    click.secho(rep)


@cli.command("generate")
@click.option("--sync", help="Update existing config", is_flag=True, default=False)
@click.argument("config-file", type=click.Path(), default=".fuzz.yml", nargs=1)
@trace("fuzz_config_generate")
def generate_config(config_file, sync: bool) -> None:
    """Generate config file for fuzzing. If `config-file` argument is provided, it will be used as a config file name.
    If --sync option is provided, existing config file will be updated.
    Params:
        config-file: path to config file
        sync: If true, update existing config file
    """
    cfs = style(config_file, fg="yellow")
    if sync:
        config_file = Path.cwd().joinpath(config_file)
        if not config_file.exists() or not config_file.is_file():
            command = style(
                f"fuzz generate-config {config_file}", italic=True, fg="green"
            )
            raise click.UsageError(
                f"⚠️  Config file {cfs} does not exist. "
                f"Please create one either manually or using {command} command"
            )
        return sync_config(config_file)
    if Path(config_file).exists():
        command = style(
            f"fuzz generate-config {config_file} --sync", italic=True, fg="green"
        )
        raise click.UsageError(
            f"⚠️  Config file {cfs} already exists. "
            f"Please specify another file or run {command} to update one."
        )
    recreate_config(config_file)
