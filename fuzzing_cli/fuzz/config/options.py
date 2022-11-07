import base64
import math
from pathlib import Path
from typing import List, Optional, Tuple, Union

import click

from fuzzing_cli.fuzz.config.pytimer import str_to_sec


class FuzzingOptions:
    def __init__(
        self,
        ide: Optional[str] = None,
        quick_check: bool = False,
        build_directory: Optional[str] = None,
        sources_directory: Optional[str] = None,
        deployed_contract_address: Optional[str] = None,
        targets: Optional[List[str]] = None,
        map_to_original_source: bool = False,
        rpc_url: str = "http://localhost:7545",
        faas_url: str = "https://fuzzing.diligence.tools",
        number_of_cores: int = 2,
        campaign_name_prefix: str = "untitled",
        corpus_target: Optional[str] = None,
        additional_contracts_addresses: Optional[Union[List[str], str]] = None,
        dry_run: bool = False,
        key: Optional[str] = None,
        project: Optional[str] = None,
        truffle_executable_path: Optional[str] = None,
        incremental: bool = False,
        time_limit: Optional[str] = None,
    ):
        self.ide: Optional[str] = ide and ide.lower()
        self.quick_check = quick_check
        self.corpus_target = corpus_target
        self.map_to_original_source = map_to_original_source
        self.dry_run = dry_run
        self.build_directory: Path = self.make_absolute_path(build_directory)
        self.sources_directory: Optional[Path] = self.make_absolute_path(
            sources_directory
        )
        self.deployed_contract_address = deployed_contract_address
        self.target: List[str] = targets
        self.rpc_url = rpc_url
        self.faas_url = faas_url
        self.number_of_cores = int(number_of_cores)
        self.campaign_name_prefix = campaign_name_prefix
        self.truffle_executable_path = truffle_executable_path
        self.project = project
        self.incremental = incremental
        self.time_limit = self._parse_time_limit(time_limit)

        self.auth_endpoint = None
        self.refresh_token = None
        self.auth_client_id = None

        self.validate(key)

        if type(additional_contracts_addresses) == str:
            self.additional_contracts_addresses: Optional[List[str]] = [
                a.strip() for a in additional_contracts_addresses.split(",")
            ]
        else:
            self.additional_contracts_addresses = additional_contracts_addresses

        self.auth_endpoint, self.auth_client_id, self.refresh_token = self._decode_refresh_token(
            key
        )

    @staticmethod
    def _parse_time_limit(time_limit: Optional[str]) -> Optional[int]:
        if not time_limit:
            return None
        try:
            return math.floor(str_to_sec(time_limit))
        except Exception as e:
            raise click.exceptions.UsageError(
                "Error parsing `time_limit` config parameter. Make sure the string in the correct format "
                '(e.g. "5d 3h 50m 15s 20ms 6us" or "24hrs,30mins")'
            ) from e

    @staticmethod
    def make_absolute_path(path: Optional[str] = None) -> Optional[Path]:
        if not path:
            return None
        if Path(path).is_absolute():
            return Path(path)
        return Path.cwd().joinpath(path)

    @classmethod
    def parse_obj(cls, obj):
        return cls(**obj)

    @staticmethod
    def _decode_refresh_token(refresh_token: str) -> Tuple[str, str, str]:
        error_message = (
            "API Key is malformed. The format is `<auth_data>::<refresh_token>`"
        )
        # format is "<auth_data>::<refresh_token>"
        if refresh_token.count("::") != 1:
            raise click.exceptions.UsageError(error_message)
        data, rt = refresh_token.split("::")
        if not data or not rt:
            raise click.exceptions.UsageError(error_message)
        try:
            decoded_data = base64.b64decode(data).decode()
        except:
            raise click.exceptions.UsageError(error_message)
        if decoded_data.count("::") != 1:
            raise click.exceptions.UsageError(error_message)
        client_id, endpoint = decoded_data.split("::")
        if not client_id or not endpoint:
            raise click.exceptions.UsageError(error_message)
        return endpoint, client_id, rt

    def validate(self, key: Optional[str] = None):
        if not self.build_directory:
            raise click.exceptions.UsageError(
                "Build directory not provided. You need to set the `build_directory` "
                "under the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.sources_directory:
            click.secho(
                "Warning: Sources directory not specified. Using IDE defaults. For a proper seed state check "
                "please set the `sources_directory` under the `fuzz` key of your .fuzz.yml config file."
            )

        if not key:
            raise click.exceptions.UsageError(
                "API key was not provided. You need to provide an API key as the `--key` parameter "
                "of the `fuzz run` command or set the `key` under the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.quick_check and not self.deployed_contract_address:
            raise click.exceptions.UsageError(
                "Deployed contract address not provided. You need to provide an address as the `--address` "
                "parameter of the fuzz run command.\nYou can also set the `deployed_contract_address`"
                "on the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.target:
            raise click.exceptions.UsageError(
                "Target not provided. You need to provide a target as the last parameter of the fuzz run command."
                "\nYou can also set the `targets` on the `fuzz` key of your .fuzz.yml config file."
            )

        if self.incremental and not self.project:
            raise click.exceptions.UsageError(
                "`incremental` config parameter is set to true without specifying `project`. "
                "Please provide the `project` in your .fuzz.yml config file."
            )
        if self.incremental and self.corpus_target:
            raise click.exceptions.UsageError(
                "Both `incremental` and `corpus_target` are set. Please set only one option in your config file"
            )
