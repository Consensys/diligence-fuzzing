import json
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch


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
    import_remaps: bool = False,
    deployed_contract_address="0x7277646075fa72737e1F6114654C5d9949a67dF2",
):
    config_file = ""
    if import_remaps:
        config_file += "analyze:"
        config_file += "\n  remappings:"
        config_file += '\n    - "@openzeppelin=lib/openzeppelin-contracts"'

    config_file += "\nfuzz:"
    if ide:
        config_file += f'\n  ide: {ide}'
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
        config_file += f'\n  api_key:\n    "test"'
    if "build_directory" not in not_include:
        config_file += f"\n  build_directory: {base_path}/{build_directory}"
    if "sources_directory" not in not_include:
        config_file += f"\n  sources_directory: {base_path}/{sources_directory}"
    if "targets" not in not_include:
        config_file += f'\n  targets:\n    - "{base_path}/{targets}"'

    if add_refresh_token:
        config_file += (
            f'\n  refresh_token: "dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2"'
        )

    return config_file


def write_config(*args, **kwargs):
    with open(".fuzz.yml", "w+") as conf_f:
        conf_f.write(generate_fuzz_config(*args, **kwargs))
