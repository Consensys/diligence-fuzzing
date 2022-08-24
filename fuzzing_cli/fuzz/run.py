import logging
import traceback
from typing import Optional

import click
from click import ClickException, UsageError

from .config import FuzzingOptions
from .exceptions import EmptyArtifactsError, FaaSError
from .faas import FaasClient
from .ide import IDEArtifacts, IDERepository
from .quickcheck_lib.quickcheck import QuickCheck, prepare_seed_state
from .rpc.rpc import RPCClient

LOGGER = logging.getLogger("fuzzing-cli")

headers = {"Content-Type": "application/json"}


@click.command("run")
@click.argument("target", default=None, nargs=-1)
@click.option(
    "-d",
    "--ide",
    type=click.STRING,
    default=None,
    help=f"Project's IDE. Valid values - {', '.join(IDERepository.get_instance().ides.keys())}",
)
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
@click.option(
    "--truffle-path",
    type=click.STRING,
    default=None,
    help="[Optional] Truffle executable path (e.g. ./node_modules/.bin/truffle)",
)
@click.pass_obj
def fuzz_run(
    ctx,
    target,
    ide: Optional[str],
    address: str,
    more_addresses: str,
    corpus_target: str,
    dry_run,
    api_key,
    key,
    refresh_token,
    map_to_original_source,
    project,
    truffle_path: Optional[str],
):
    """Submit contracts to the Diligence Fuzzing API"""
    analyze_config = ctx.get("analyze", {}) or {}
    fuzz_config = ctx.get("fuzz", {}) or {}

    if fuzz_config.get("api_key") or api_key:
        LOGGER.warning(
            "The --api-key parameter and 'api_key' configuration file option value have been"
            " deprecated. You should use the --key and 'key' options instead."
        )

    if fuzz_config.get("refresh_token") or refresh_token:
        LOGGER.warning(
            "The --refresh-token parameter and 'refresh_token' configuration file option have been"
            " deprecated. You should use the --key and 'key' options instead."
        )

    options = FuzzingOptions.parse_obj(
        {
            k: v
            for k, v in (
                {
                    "ide": ide or fuzz_config.get("ide"),
                    "quick_check": fuzz_config.get("quick_check", False),
                    "build_directory": fuzz_config.get("build_directory"),
                    "sources_directory": fuzz_config.get("sources_directory"),
                    "deployed_contract_address": address
                    or fuzz_config.get("deployed_contract_address"),
                    "targets": target or fuzz_config.get("targets"),
                    "map_to_original_source": map_to_original_source,
                    "rpc_url": fuzz_config.get("rpc_url"),
                    "faas_url": fuzz_config.get("faas_url"),
                    "number_of_cores": fuzz_config.get("number_of_cores"),
                    "campaign_name_prefix": fuzz_config.get("campaign_name_prefix"),
                    "corpus_target": corpus_target or fuzz_config.get("corpus_target"),
                    "additional_contracts_addresses": more_addresses
                    or fuzz_config.get("additional_contracts_addresses"),
                    "dry_run": dry_run,
                    "key": key
                    or fuzz_config.get("key")
                    or api_key
                    or fuzz_config.get("api_key")
                    or refresh_token
                    or fuzz_config.get("refresh_token"),
                    "project": project or fuzz_config.get("project"),
                    "truffle_executable_path": truffle_path,
                    "incremental": fuzz_config.get("incremental"),
                    "suggested_seed_seqs": fuzz_config.get("suggested_seed_seqs"),
                    "lesson_description": fuzz_config.get("lesson_description"),
                    "time_limit": fuzz_config.get("time_limit"),
                }
            ).items()
            if v is not None
        }
    )

    _corpus_target = options.corpus_target
    if options.incremental:
        _corpus_target = options.project

    if options.quick_check:
        project_type: str = "QuickCheck"
        artifacts: IDEArtifacts = QuickCheck(
            options=options,
            scribble_path=analyze_config.get("scribble-path") or "scribble",
            targets=options.target,
            build_dir=options.build_directory,
            sources_dir=options.sources_directory,
            map_to_original_source=map_to_original_source
            or options.map_to_original_source,
            remappings=analyze_config.get("remappings", []),
            solc_version=analyze_config.get("solc-version", []),
            solc_path=None,
            no_assert=analyze_config.get("no-assert", False),
        )
        seed_state = prepare_seed_state(
            artifacts.contracts, options.number_of_cores, _corpus_target
        )
    else:
        rpc_client = RPCClient(options.rpc_url, options.number_of_cores)

        seed_state = rpc_client.get_seed_state(
            options.deployed_contract_address,
            options.additional_contracts_addresses,
            _corpus_target,
        )

        repo = IDERepository.get_instance()
        if options.ide:
            LOGGER.debug(f'"{options.ide}" IDE is specified')
            _IDEClass = repo.get_ide(options.ide)
        else:
            LOGGER.debug("IDE not specified. Detecting one")
            _IDEClass = repo.detect_ide()
            if not _IDEClass:
                LOGGER.debug("No supported IDE was detected")
                raise UsageError(f"No supported IDE was detected")
            LOGGER.debug(f'"{_IDEClass.get_name()}" IDE detected')

        artifacts: IDEArtifacts = _IDEClass(
            options=options,
            targets=options.target,
            build_dir=options.build_directory or _IDEClass.get_default_build_dir(),
            sources_dir=options.sources_directory
            or _IDEClass.get_default_sources_dir(),
            map_to_original_source=options.map_to_original_source,
        )
        project_type: str = _IDEClass.get_name()

        try:
            artifacts.validate()
        except EmptyArtifactsError:
            LOGGER.debug("Empty artifacts")
            raise UsageError(
                f"No contract being submitted. Please check your config (hint: build_directory path or targets paths)"
            )

        rpc_client.check_contracts(seed_state, artifacts, options.target)

    faas_client = FaasClient(
        faas_url=options.faas_url,
        campaign_name_prefix=options.campaign_name_prefix,
        project_type=project_type,
        client_id=options.auth_client_id,
        refresh_token=options.refresh_token,
        auth_endpoint=options.auth_endpoint,
        project=options.project,
        quick_check=options.quick_check,
        time_limit=options.time_limit,
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
