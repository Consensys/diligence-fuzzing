import logging
import traceback
from typing import Any, Dict, List, Optional

import click
from click import ClickException, UsageError, style

from .config import AnalyzeOptions, FuzzingOptions, omit_none
from .corpus import CorpusRepository
from .corpus.repository import NoTransactionFound
from .exceptions import EmptyArtifactsError, FaaSError
from .faas import FaasClient
from .ide import IDEArtifacts, IDERepository
from .quickcheck_lib.quickcheck import QuickCheck, prepare_seed_state
from .rpc.rpc import RPCClient

LOGGER = logging.getLogger("fuzzing-cli")


QM = f"[{style('?', fg='yellow')}]"


def handle_validation_errors(
    corpus_repo: CorpusRepository,
    prompt: bool = True,
    smart_mode: bool = False,
) -> List[Dict[str, Any]]:
    """
    Handle validation errors from the corpus repository and prompt the user for automatic fixes if needed.
    If the user chooses to fix the errors, a list of suggested fixes is returned and the ones are applied.
    Otherwise, an exception is raised if there are any validation errors.

    :param corpus_repo: Corpus repository
    :param prompt: Whether to prompt the user for automatic fixes
    :return: List of suggested fixes
    """
    suggested_fixes = []
    for validation_error in corpus_repo.validation_errors:
        if validation_error["type"] == "unknown_contracts":
            data = "\n".join([f"  ◦ {addr}" for addr in validation_error["data"]])
            error_message = (
                f"Unable to find contracts with following addresses:\n{data}"
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nRemove ones from addresses under test?",
                    default=True,
                )
            ):
                suggested_fixes.append(
                    {"type": "remove_addresses", "data": validation_error["data"]}
                )
                continue
            raise ClickException(error_message)

        if validation_error["type"] == "contracts_with_no_artifact":
            data = "\n".join([f"  ◦ {addr}" for addr in validation_error["data"]])
            error_message = (
                f"⚠️ No artifact found for following deployed contracts:\n{data}\nThis could be due to "
                f"disabled metadata hash generation in your compiler settings."
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nRemove ones from addresses under test?",
                    default=True,
                )
            ):
                suggested_fixes.append(
                    {"type": "remove_addresses", "data": validation_error["data"]}
                )
                continue
            click.secho(error_message)
            continue

        if validation_error["type"] == "contract_target_not_set":
            data = "\n".join(
                [
                    f"  ◦ Address: {addr} Source File: {file_name} Contract Name: {contract_name}"
                    for addr, file_name, contract_name in validation_error["data"]
                ]
            )
            error_message = (
                f"The following targets were provided without providing "
                f"addresses of respective contracts as addresses under test:\n{data}"
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nAdd them to addresses under test?",
                    default=True,
                )
            ):
                suggested_fixes.append(
                    {
                        "type": "add_addresses",
                        "data": [addr for addr, _, _ in validation_error["data"]],
                    }
                )
                continue
            raise ClickException(error_message)

        if validation_error["type"] == "source_target_not_set":
            data = "\n".join(
                [
                    f"  ◦ Address: {addr} Target: {file_name}"
                    for addr, file_name in validation_error["data"]
                ]
            )
            error_message = (
                f"Following contract's addresses were provided as addresses under test "
                f"without specifying them as a target prior to `fuzz run`:\n{data}"
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nAdd them to targets?", default=True
                )
            ):
                suggested_fixes.append(
                    {
                        "type": "add_targets",
                        "data": [
                            file_name for _, file_name in validation_error["data"]
                        ],
                    }
                )
                continue
            raise ClickException(error_message)

        if validation_error["type"] == "not_deployed_contracts":
            data = "\n".join(
                [
                    f"  ◦ Source File: {file_name} Contract Name: {contract_name}"
                    for file_name, contract_name in validation_error["data"]
                ]
            )
            error_message = (
                f"⚠️ Following contracts were not deployed to RPC node:\n{data}"
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nRemove them from targets?", default=True
                )
            ):
                suggested_fixes.append(
                    {
                        "type": "remove_targets",
                        "data": [
                            file_name for file_name, _ in validation_error["data"]
                        ],
                    }
                )
                continue
            click.secho(error_message)
            continue
        if validation_error["type"] == "not_targeted_contracts":
            data = "\n".join(
                [
                    f"  ◦ Address: {addr} Source File: {file_name} Contract Name: {contract_name}"
                    for addr, file_name, contract_name in validation_error["data"]
                ]
            )
            error_message = (
                f"⚠️ Following contracts were not included into the seed state:\n{data}"
            )
            if smart_mode or (
                prompt
                and click.confirm(
                    f"{QM} {error_message}\nAdd them to targets?", default=True
                )
            ):
                suggested_fixes.extend(
                    [
                        {
                            "type": "add_targets",
                            "data": [
                                file_name
                                for _, file_name, _ in validation_error["data"]
                            ],
                        },
                        {
                            "type": "add_addresses",
                            "data": [addr for addr, _, _ in validation_error["data"]],
                        },
                    ]
                )
                continue
            click.secho(error_message)
            continue
    return suggested_fixes


@click.command("run")
@click.argument("targets", default=None, nargs=-1)
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
    default=None,
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
    "-k",
    "--key",
    type=click.STRING,
    default=None,
    help="API key, can be created on the FaaS Dashboard. ",
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
@click.option(
    "--no-prompts",
    is_flag=True,
    default=False,
    help="Do not prompt for user input (to suggest an auto fix, for example). Instead, "
    "fail if any of the validation errors are encountered. (CI/CD mode)",
)
def fuzz_run(
    targets,
    ide: Optional[str],
    address: str,
    more_addresses: str,
    corpus_target: str,
    dry_run,
    key,
    map_to_original_source,
    project,
    truffle_path: Optional[str],
    no_prompts: bool,
):
    """Submit contracts to the Diligence Fuzzing API"""

    options = FuzzingOptions(
        **omit_none(
            {
                "ide": ide,
                "deployed_contract_address": address,
                "additional_contracts_addresses": more_addresses,
                "targets": targets if len(targets) > 0 else None,
                "map_to_original_source": map_to_original_source,
                "corpus_target": corpus_target,
                "dry_run": dry_run,
                "key": key,
                "project": project,
                "truffle_executable_path": truffle_path,
            }
        ),
        no_prompts=no_prompts,
    )

    _corpus_target = options.corpus_target
    if options.incremental:
        _corpus_target = options.project

    if options.quick_check:
        analyze_options = AnalyzeOptions()
        project_type: str = "QuickCheck"
        artifacts: IDEArtifacts = QuickCheck(
            options=options,
            scribble_path=analyze_options.scribble_path,
            targets=options.targets,
            build_dir=options.build_directory,
            sources_dir=options.sources_directory,
            map_to_original_source=options.map_to_original_source,
            remappings=analyze_options.remappings,
            solc_version=analyze_options.solc_version,
            solc_path=None,
            no_assert=analyze_options.no_assert,
        )
        seed_state = prepare_seed_state(
            artifacts.contracts, options.number_of_cores, _corpus_target
        )
    else:
        rpc_client = RPCClient(options.rpc_url, options.number_of_cores)

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
            build_dir=options.build_directory or _IDEClass.get_default_build_dir(),
            sources_dir=options.sources_directory
            or _IDEClass.get_default_sources_dir(),
            map_to_original_source=options.map_to_original_source,
        )
        project_type: str = _IDEClass.get_name()

        corpus_repo = CorpusRepository(rpc_client, artifacts, options, _corpus_target)
        # if the no_prompts flag is set, we need to fail if there are any validation errors
        suggested_fixes = handle_validation_errors(
            corpus_repo, prompt=not no_prompts, smart_mode=options.smart_mode
        )
        if suggested_fixes:
            corpus_repo.apply_auto_fix(suggested_fixes)
            # after applying the fixes, we need to revalidate the corpus
            # and if there are still errors, we need to abort and raise an error
            # because we could end up in an infinite loop of fixes that don't work
            handle_validation_errors(corpus_repo, prompt=False)
        try:
            seed_state = corpus_repo.seed_state
        except NoTransactionFound:
            raise click.exceptions.UsageError(
                f"Unable to generate the seed state. "
                f"No transactions were found in an ethereum node running at {options.rpc_url}"
            )
        except Exception as e:
            LOGGER.warning(f"Could not generate seed state for address")
            raise click.exceptions.UsageError(
                (
                    "Unable to generate the seed state. Are you sure you passed the correct contract address?"
                )
            ) from e
        # narrow down the artifacts to the ones that are in the corpus specified by the target
        artifacts = artifacts.instance_for_targets(
            artifacts, corpus_repo.source_targets
        )

        try:
            artifacts.validate()
        except EmptyArtifactsError:
            LOGGER.debug("Empty artifacts")
            raise UsageError(
                f"No contract being submitted. Please check your config (hint: build_directory path or targets paths) "
                f"or recompile contracts"
            )

    return submit_campaign(options, project_type, artifacts, seed_state)


def submit_campaign(
    options: FuzzingOptions,
    project_type: str,
    artifacts: IDEArtifacts,
    seed_state: Dict[str, any],
) -> None:
    faas_client = FaasClient(options=options, project_type=project_type)

    try:
        campaign_id = faas_client.create_faas_campaign(
            campaign_data=artifacts, seed_state=seed_state
        )
        if options.dry_run:
            return
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
