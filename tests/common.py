import json
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import List
from unittest.mock import patch

from mythx_models.response import (
    AnalysisInputResponse,
    AnalysisListResponse,
    AnalysisStatusResponse,
    AnalysisSubmissionResponse,
    DetectedIssuesResponse,
    GroupCreationResponse,
    GroupListResponse,
    GroupStatusResponse,
    VersionResponse,
)


def get_test_case(path: str, obj=None, raw=False):
    with open(str(Path(__file__).parent / path)) as f:
        if raw:
            return f.read()
        dict_data = json.load(f)

    if obj is None:
        return dict_data

    if obj is DetectedIssuesResponse and type(dict_data) is list:
        return obj(issue_reports=dict_data)
    else:
        return obj(**dict_data)


AST = get_test_case("testdata/test-ast.json")


@contextmanager
def mock_faas_context():
    with patch("mythx_cli.fuzz.rpc.RPCClient") as RPCClient_mock:
        instance = RPCClient_mock.return_value
        instance.get_all_blocks.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        instance.contract_exists.return_value = True
    yield


@contextmanager
def mock_context(
    submission_response=None,
    issues_response=None,
    input_response=None,
    analysis_list_response=None,
    group_list_response=None,
    analysis_status_response=None,
    group_status_response=None,
    group_creation_response=None,
):
    with patch("pythx.Client.analyze") as analyze_patch, patch(
        "pythx.Client.analysis_ready"
    ) as ready_patch, patch("pythx.Client.report") as report_patch, patch(
        "pythx.Client.request_by_uuid"
    ) as input_patch, patch(
        "solcx.compile_source"
    ) as compile_patch, patch(
        "pythx.Client.analysis_list"
    ) as analysis_list_patch, patch(
        "pythx.Client.group_list"
    ) as group_list_patch, patch(
        "pythx.Client.analysis_status"
    ) as status_patch, patch(
        "pythx.Client.group_status"
    ) as group_status_patch, patch(
        "pythx.Client.create_group"
    ) as group_create_patch, patch(
        "pythx.Client.version"
    ) as version_patch:
        analyze_patch.return_value = submission_response or get_test_case(
            "testdata/analysis-submission-response.json", AnalysisSubmissionResponse
        )
        ready_patch.return_value = True
        report_patch.return_value = deepcopy(issues_response) or get_test_case(
            "testdata/detected-issues-response.json", DetectedIssuesResponse
        )
        input_patch.return_value = input_response or get_test_case(
            "testdata/analysis-input-response.json", AnalysisInputResponse
        )
        compile_patch.return_value = {
            "contract": {
                "abi": "test",
                "ast": AST,
                "bin": "test",
                "bin-runtime": "test",
                "srcmap": "test",
                "srcmap-runtime": "test",
            }
        }
        analysis_list_patch.return_value = analysis_list_response or get_test_case(
            "testdata/analysis-list-response.json", AnalysisListResponse
        )
        group_list_patch.return_value = group_list_response or get_test_case(
            "testdata/group-list-response.json", GroupListResponse
        )
        status_patch.return_value = analysis_status_response or get_test_case(
            "testdata/analysis-status-response.json", AnalysisStatusResponse
        )
        group_status_patch.return_value = group_status_response or get_test_case(
            "testdata/group-status-response.json", GroupStatusResponse
        )
        group_create_patch.return_value = group_creation_response or get_test_case(
            "testdata/group-creation-response.json", GroupCreationResponse
        )
        version_patch.return_value = get_test_case(
            "testdata/version-response.json", VersionResponse
        )
        yield (
            analyze_patch,
            ready_patch,
            report_patch,
            input_patch,
            compile_patch,
            analysis_list_patch,
            group_list_patch,
            status_patch,
            group_status_patch,
            group_create_patch,
            version_patch,
        )


def generate_mythx_config(
    base_path: str = "",
    build_directory: str = "build",
    targets: str = "contracts",
    not_include: List[str] = [],
    add_refresh_token: bool = False,
):
    config_file = "fuzz:"
    if "deployed_contract_address" not in not_include:
        config_file += '\n  deployed_contract_address: "0x7277646075fa72737e1F6114654C5d9949a67dF2"'
    if "number_of_cores" not in not_include:
        config_file += "\n  number_of_cores: 1"
    if "campaign_name_prefix" not in not_include:
        config_file += '\n  campaign_name_prefix: "ide_test"'
    if "rpc_url" not in not_include:
        config_file += f'\n  rpc_url: "http://localhost:9898"'
    if "faas_url" not in not_include:
        config_file += f'\n  faas_url: "http://localhost:9899"'
    if "api_key" not in not_include:
        config_file += f'\n  api_key:\n    "test"'
    if "build_directory" not in not_include:
        config_file += f"\n  build_directory: {base_path}/{build_directory}"
    if "targets" not in not_include:
        config_file += f'\n  targets:\n    - "{base_path}/{targets}"'

    if add_refresh_token:
        config_file += (
            f'\n  refresh_token: "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"'
        )

    return config_file


def write_config(*args, **kwargs):
    with open(".mythx.yml", "w+") as conf_f:
        conf_f.write(generate_mythx_config(*args, **kwargs))
