import json
import platform
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple, Union
from unittest.mock import patch

import requests
import requests_mock
from deepdiff import DeepDiff

from fuzzing_cli.fuzz.types import EVMBlock


def get_test_case(path: str, obj=None, raw=False):
    with open(str(Path(__file__).parent / path)) as f:
        if raw:
            return f.read()
        dict_data = json.load(f)

    if obj is None:
        return dict_data

    return obj(**dict_data)


@contextmanager
def mock_faas_context():
    with patch("fuzzing_cli.fuzz.rpc.RPCClient") as RPCClient_mock:
        instance = RPCClient_mock.return_value
        instance.get_all_blocks.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
    yield


def generate_fuzz_config(
    ide: Optional[str] = None,
    base_path: str = "",
    build_directory: str = "build",
    sources_directory: str = "contracts",
    targets: str = "contracts",
    not_include: List[str] = [],
    add_refresh_token: bool = False,
    deployed_contract_address="0x7277646075fa72737e1F6114654C5d9949a67dF2",
    project: Optional[str] = None,
    incremental: Optional[bool] = None,
    corpus_target: Optional[str] = None,
    additional_addresses: List[str] = [],
    absolute_targets: bool = True,
    absolute_build_directory: bool = True,
    absolute_sources_directory: bool = True,
    remappings: List[str] = [],
    solc_version: Optional[str] = None,
    no_assert: Optional[bool] = None,
    scribble_path: Optional[str] = None,
    quick_check: Optional[bool] = None,
    faas_url: Optional[str] = None,
    suggested_seed_seqs: Optional[List[Mapping[str, any]]] = None,
    time_limit: Optional[str] = None,
):
    config_file = "analyze:"
    if remappings:
        _data = "\n".join([f'    - "{r}"' for r in remappings])
        config_file += f"\n  remappings:\n{_data}"
    if solc_version:
        config_file += f"\n  solc-version: {solc_version}"
    if no_assert is not None:
        config_file += f"\n  no-assert: {str(no_assert).lower()}"
    if scribble_path is not None:
        config_file += f"\n  scribble-path: {scribble_path}"

    config_file += "\nfuzz:"
    if ide:
        config_file += f"\n  ide: {ide}"
    if "deployed_contract_address" not in not_include:
        config_file += f'\n  deployed_contract_address: "{deployed_contract_address}"'
    if "number_of_cores" not in not_include:
        config_file += "\n  number_of_cores: 1"
    if "campaign_name_prefix" not in not_include:
        config_file += '\n  campaign_name_prefix: "ide_test"'
    if "rpc_url" not in not_include:
        config_file += f'\n  rpc_url: "http://localhost:9898"'
    if "faas_url" not in not_include:
        config_file += f'\n  faas_url: "http://localhost:9899"'
    if "api_key" not in not_include:
        config_file += (
            f'\n  key:\n    "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"'
        )
    if "build_directory" not in not_include:
        if absolute_build_directory:
            config_file += f"\n  build_directory: {base_path}/{build_directory}"
        else:
            config_file += f"\n  build_directory: {build_directory}"
    if "sources_directory" not in not_include:
        if absolute_sources_directory:
            config_file += f"\n  sources_directory: {base_path}/{sources_directory}"
        else:
            config_file += f"\n  sources_directory: {sources_directory}"
    if "targets" not in not_include:
        if absolute_targets:
            _data = "\n".join([f'    - "{base_path}/{t}"' for t in targets])
        else:
            _data = "\n".join([f'    - "{t}"' for t in targets])
        config_file += f"\n  targets:\n{_data}"

    if project is not None:
        config_file += f"\n  project: {project}"

    if incremental is not None:
        config_file += f"\n  incremental: {incremental}"

    if corpus_target is not None:
        config_file += f"\n  corpus_target: {corpus_target}"

    if suggested_seed_seqs is not None:
        mapping_str = ""
        for s in suggested_seed_seqs:
            mapping = [f"\n    {key}: {val}" for key, val in s.items()]
            mapping[0] = "\n  - " + mapping[0][5:]  # first entry of the list
            mapping_str += "".join(mapping)

        config_file += f"\n  suggested_seed_seqs:{mapping_str}"

    if additional_addresses:
        _data = "\n".join([f'    - "{a}"' for a in additional_addresses])
        config_file += f"\n  additional_contracts_addresses:\n{_data}"

    if add_refresh_token:
        config_file += (
            f'\n  refresh_token: "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"'
        )
    if time_limit:
        config_file += f"\n  time_limit: 15min"

    if quick_check:
        config_file += f"\n  quick_check: true"

    if faas_url:
        config_file += f"\n  faas_url: {faas_url}"

    if time_limit:
        config_file += f"\n  time_limit: {time_limit}"

    return config_file


def write_config(config_path=".fuzz.yml", *args, **kwargs):
    with open(config_path, "w+") as conf_f:
        conf_f.write(generate_fuzz_config(*args, **kwargs))


def get_code_mocker(contracts: Dict[str, any]):
    _contracts = {}
    for contract_name, data in contracts.items():
        address = data["address"].lower()
        _contracts[address] = data["deployedBytecode"]

    def mock(address: str):
        return _contracts.get(address.lower(), None)

    return mock


@contextmanager
def mocked_rpc_client(blocks: List[EVMBlock], codes: Dict[str, str] = {}):
    def request_handler(request: requests.Request, context):
        payload: Dict[str, any] = json.loads(request.text)
        method = payload.get("method")
        params = payload.get("params")
        context.status_code = 200
        response_body = {"id": 1, "jsonrpc": "2.0", "result": None}
        if method == "eth_getBlockByNumber":
            if params[0] == "latest":
                return {**response_body, "result": blocks[-1]}
            return {**response_body, "result": blocks[int(params[0], 16)]}
        elif method == "eth_getCode":
            contract_address = params[0]
            return {**response_body, "result": codes.get(contract_address, None)}
        elif method == "eth_getBlockByHash":
            block_hash = params[0]
            for b in blocks:
                if b["hash"] == block_hash:
                    return {**response_body, "result": b}
            return {**response_body, "result": None}
        return response_body

    with requests_mock.Mocker() as m:
        m.register_uri("POST", "http://localhost:9898", json=request_handler)
        yield


def assert_is_equal(
    a: Union[List[any], Dict[str, any]], b: Union[List[any], Dict[str, any]]
):
    res = DeepDiff(a, b, ignore_order=True, report_repetition=True)
    assert res == {}, f"{res}"


def get_python_version() -> Tuple[str, str]:
    return (
        platform.python_implementation(),
        f"{sys.version_info.major}.{sys.version_info.minor}",
    )
