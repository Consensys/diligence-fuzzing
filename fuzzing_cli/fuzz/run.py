import logging
import os
import traceback
from enum import Enum
from pathlib import Path

import click
from click import ClickException, UsageError

from .exceptions import FaaSError, RPCCallError
from .faas import FaasClient
from .ide import BrownieJob, HardhatJob, TruffleJob
from .options import FuzzingOptions
from .rpc import RPCClient

LOGGER = logging.getLogger("fuzzing-cli")

headers = {"Content-Type": "application/json"}

time_limit_seconds = 3000


class IDE(Enum):
    BROWNIE = "brownie"
    HARDHAT = "hardhat"
    TRUFFLE = "truffle"
    SOLIDITY = "solidity"


def determine_ide() -> IDE:
    root_dir = Path.cwd().absolute()
    files = list(os.walk(root_dir))[0][2]
    if "brownie-config.yaml" in files:
        return IDE.BROWNIE
    if "hardhat.config.ts" in files:
        return IDE.HARDHAT
    if "hardhat.config.js" in files:
        return IDE.HARDHAT
    if "truffle-config.js" in files:
        return IDE.TRUFFLE
    return IDE.SOLIDITY


def check_contract(rpc_client: RPCClient, deployed_contract_address: str):
    try:
        contract_code_response = rpc_client.contract_exists(deployed_contract_address)
    except RPCCallError as e:
        raise UsageError(f"{e}")

    if not contract_code_response:
        raise ClickException(
            f"Unable to find a contract deployed at {deployed_contract_address}"
        )


@click.command("run")
@click.argument("target", default=None, nargs=-1)
@click.option(
    "-a",
    "--address",
    type=click.STRING,
    default=None,
    help="Address of the main contract to analyze",
)
@click.option(
    "-m",
    "--more-addresses",
    type=click.STRING,
    default=None,
    help="Addresses of other contracts to analyze, separated by commas",
)
@click.option(
    "-c",
    "--corpus-target",
    type=click.STRING,
    help="Project UUID, Campaign UUID or Corpus UUID to reuse the corpus from. "
    "In case of a project, corpus from the project's latest submitted campaign will be used",
    default=None,
)
@click.option(
    "-s",
    "--map-to-original-source",
    is_flag=True,
    default=False,
    required=False,
    help="Map the analyses results to the original source code, instead of the instrumented one. "
    "This is meant to be used with Scribble.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Outputs the data to be sent to the FaaS API without making the request.",
)
@click.option(
    "--api-key",
    type=click.STRING,
    default=None,
    help="API key, can be created on the FaaS Dashboard. ",
    hidden=True,
)
@click.option(
    "-k",
    "--key",
    type=click.STRING,
    default=None,
    help="API key, can be created on the FaaS Dashboard. ",
)
@click.option(
    "--refresh-token",
    type=click.STRING,
    default=None,
    help="Refresh Token, can be created on the FaaS Dashboard. ",
    hidden=True,
)
@click.option(
    "-p",
    "--project",
    type=click.STRING,
    default=None,
    help="The project name this campaign will be attached to. You can use the project name or the project id."
    "Alternatively, you may also configure the 'project' field in the .fuzz.yml configuration file."
    "If no project is configured the scan will be attached to the 'Default Project'.",
)
@click.pass_obj
def fuzz_run(
    ctx,
    target,
    address,
    more_addresses,
    corpus_target,
    dry_run,
    api_key,
    key,
    refresh_token,
    map_to_original_source,
    project,
):
    if not key and refresh_token:
        key = refresh_token
    analyze_config = ctx.get("fuzz")

    if analyze_config.get("api_key") or api_key:
        LOGGER.warning(
            "The --api-key parameter and 'api_key' configuration file option value have been"
            " deprecated. You should use the --key and 'key' options instead."
        )

    if analyze_config.get("refresh_token") or refresh_token:
        LOGGER.warning(
            "The --refresh-token parameter and 'refresh_token' configuration file option have been"
            " deprecated. You should use the --key and 'key' options instead."
        )

    options = FuzzingOptions(
        **{
            k: v
            for k, v in (
                {
                    "build_directory": analyze_config.get("build_directory"),
                    "deployed_contract_address": address
                    or analyze_config.get("deployed_contract_address"),
                    "target": target or analyze_config.get("targets"),
                    "map_to_original_source": map_to_original_source,
                    "rpc_url": analyze_config.get("rpc_url"),
                    "faas_url": analyze_config.get("faas_url"),
                    "number_of_cores": analyze_config.get("number_of_cores"),
                    "campaign_name_prefix": analyze_config.get("campaign_name_prefix"),
                    "corpus_target": corpus_target
                    or analyze_config.get("corpus_target"),
                    "additional_contracts_addresses": more_addresses
                    or analyze_config.get("additional_contracts_addresses"),
                    "dry_run": dry_run,
                    "refresh_token": key
                    or analyze_config.get("key")
                    or analyze_config.get("refresh_token"),
                    "api_key": api_key or analyze_config.get("api_key"),
                    "project": project or analyze_config.get("project"),
                }
            ).items()
            if v is not None
        }
    )

    rpc_client = RPCClient(options.rpc_url, options.number_of_cores)
    if not options.corpus_target:
        check_contract(rpc_client, options.deployed_contract_address)

    seed_state = rpc_client.get_seed_state(
        options.deployed_contract_address,
        options.additional_contracts_addresses,
        options.corpus_target,
    )

    ide = determine_ide()

    if ide == IDE.BROWNIE:
        artifacts = BrownieJob(
            options.target,
            Path(options.build_directory),
            map_to_original_source=options.map_to_original_source,
        )
        artifacts.generate_payload()
    elif ide == IDE.HARDHAT:
        artifacts = HardhatJob(
            options.target,
            Path(options.build_directory),
            map_to_original_source=options.map_to_original_source,
        )
        artifacts.generate_payload()
    elif ide == IDE.TRUFFLE:
        artifacts = TruffleJob(
            str(Path.cwd().absolute()), options.target, Path(options.build_directory)
        )
        artifacts.generate_payload()
    else:
        raise UsageError(
            f"Projects using plain solidity files is not supported right now"
        )

    faas_client = FaasClient(
        faas_url=options.faas_url,
        campaign_name_prefix=options.campaign_name_prefix,
        project_type=ide,
        api_key=options.api_key,
        client_id=options.auth_client_id,
        refresh_token=options.refresh_token,
        auth_endpoint=options.auth_endpoint,
        project=options.project,
    )

    try:
        campaign_id = faas_client.create_faas_campaign(
            campaign_data=artifacts, seed_state=seed_state, dry_run=options.dry_run
        )
        click.echo(
            "You can view campaign here: "
            + options.faas_url
            + "/campaigns/"
            + str(campaign_id)
        )
    except Exception as e:
        if isinstance(e, FaaSError):
            raise ClickException(
                message=f"{type(e).__name__}: {e.message}\nDetail: {e.detail}"
            )

        LOGGER.warning(
            f"Could not submit campaign to the FaaS\n{traceback.format_exc()}"
        )
        raise ClickException(message=f"Unhandled exception - {str(e)}")
