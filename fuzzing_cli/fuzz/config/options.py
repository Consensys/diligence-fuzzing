import base64
import logging
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import click
import yaml
from pydantic import BaseSettings, Field, ValidationError, root_validator, validator

from .pytimer import str_to_sec

LOGGER = logging.getLogger("fuzzing-cli")


def repr_errors(error: ValidationError) -> str:
    errors = []
    for err in error.errors():
        if err.get("type") == "value_error.missing":
            errors.append(f"Missing required option: {err.get('loc', [])[0]}")
        elif err.get("type") == "value_error":
            errors.append(err.get("msg", "Value Error"))
        else:
            errors.append(str(err))
    return ", ".join(errors)


def yaml_config_settings_source(key="fuzz"):
    def loader(_) -> Dict[str, Any]:
        # this env variable is set by -c option in the cli (e.g. fuzz -c .fuzz-test.yaml run,
        # or FUZZ_CONFIG_FILE=.fuzz-test.yaml)
        config_path = os.environ.get("FUZZ_CONFIG_FILE", ".fuzz.yml")
        if Path(config_path).is_file():
            LOGGER.debug(f"Parsing config at {config_path}")
            with open(config_path) as config_f:
                parsed_config = yaml.safe_load(config_f.read())
                return parsed_config.get(key, {}) or {}
        return {}

    return loader


class FuzzingOptions(BaseSettings):
    ide: Optional[str] = None
    build_directory: Optional[Path] = None
    sources_directory: Optional[Path] = None

    key: Optional[str] = Field(None, env="FUZZ_API_KEY")

    project: Optional[str] = None
    corpus_target: Optional[str] = None
    number_of_cores: int = 1
    time_limit: Optional[str] = None

    targets: Optional[List[str]] = None
    deployed_contract_address: Optional[str] = None
    additional_contracts_addresses: Optional[Union[List[str], str]] = None
    rpc_url: str = "http://localhost:7545"

    campaign_name_prefix: str = "untitled"
    map_to_original_source: bool = False

    enable_cheat_codes: Optional[bool] = None
    chain_id: Optional[str] = None
    incremental: bool = False
    truffle_executable_path: Optional[str] = None
    quick_check: bool = False

    faas_url: str = Field("https://fuzzing.diligence.tools", exclude=True)
    foundry_tests: bool = False
    foundry_tests_list: Optional[Dict[str, Dict[str, List[str]]]] = None
    target_contracts: Optional[Dict[str, Set[str]]] = None

    dry_run: bool = False

    no_build_directory: bool = Field(False, exclude=True)
    no_key: bool = Field(False, exclude=True)
    no_deployed_contract_address: bool = Field(False, exclude=True)
    no_targets: bool = Field(False, exclude=True)

    def __init__(self, *args, **data: Any):
        try:
            super().__init__(*args, **data)
        except ValidationError as e:
            raise click.exceptions.UsageError(f"Invalid config: {repr_errors(e)}")
        except:
            raise

    @property
    def _parsed_key(self):
        data, rt = self.key.split("::")
        decoded_data = base64.b64decode(data).decode()
        client_id, endpoint = decoded_data.split("::")
        return endpoint, client_id, rt

    @property
    def auth_endpoint(self):
        return self._parsed_key[0]

    @property
    def auth_client_id(self):
        return self._parsed_key[1]

    @property
    def refresh_token(self):
        return self._parsed_key[2]

    class Config:
        env_prefix = "fuzz_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        allow_population_by_field_name = True

        @classmethod
        def customise_sources(
            cls,
            init_settings,
            env_settings,
            file_secret_settings,
        ):
            # load in order (from the least priority to the highest priority):
            # 1. config settings from config file
            # 2. .env file
            # 3. environment variables
            # 4. command arguments
            return (
                init_settings,
                env_settings,
                yaml_config_settings_source(),
                file_secret_settings,
            )

    @validator("chain_id")
    def _validate_chain_id(cls, chain_id: Optional[Union[str, int]]) -> Optional[str]:
        if chain_id is None or (type(chain_id) == str and len(chain_id) == 0):
            return None
        if type(chain_id) == int:
            return hex(chain_id)
        if chain_id.startswith("0x"):
            return chain_id
        # could be a number, so try to convert it to hex
        try:
            return hex(int(chain_id))
        except ValueError:
            raise ValueError("Invalid chain id. Must be a hex string or an integer.")

    @validator("time_limit")
    def _validate_time_limit(cls, time_limit: Optional[str]) -> Optional[int]:
        if not time_limit:
            return None
        try:
            return math.floor(str_to_sec(time_limit))
        except:
            raise ValueError(
                "Error parsing `time_limit` config parameter. Make sure the string is in the correct format "
                '(e.g. "5d 3h 50m 15s 20ms 6us" or "24hrs,30mins")'
            )

    @validator("build_directory", "sources_directory")
    def _validate_paths(cls, path: Optional[str]) -> Optional[Path]:
        if not path:
            return None
        if Path(path).is_absolute():
            return Path(path)
        return Path.cwd().joinpath(path)

    @validator("additional_contracts_addresses")
    def _validate_contracts_addresses(
        cls, addresses: Optional[Union[List[str], str]]
    ) -> Optional[List[str]]:
        if not addresses:
            return None
        if type(addresses) == str:
            return [addr.strip() for addr in addresses.split(",")]
        return addresses

    @validator("key")
    def _validate_key(cls, key: Optional[str]) -> Optional[str]:
        error_message = (
            "API Key is malformed. The format is `<auth_data>::<refresh_token>`"
        )
        # format is "<auth_data>::<refresh_token>"
        if not key:
            return None
        if key.count("::") != 1:
            raise ValueError(error_message)
        data, rt = key.split("::")
        if not data or not rt:
            raise ValueError(error_message)
        try:
            decoded_data = base64.b64decode(data).decode()
        except:
            raise ValueError(error_message)
        if decoded_data.count("::") != 1:
            raise ValueError(error_message)
        client_id, endpoint = decoded_data.split("::")
        if not client_id or not endpoint:
            raise ValueError(error_message)
        return key

    @root_validator()
    def validate(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        if not values.get("no_build_directory") and not values.get("build_directory"):
            raise ValueError("Build directory not provided")
        if not values.get("sources_directory"):
            click.secho(
                "Warning: Sources directory not specified. Using IDE defaults. For a proper seed state check "
                "please set one.",
            )

        if not values.get("no_key") and not values.get("key"):
            raise ValueError("API key not provided")

        if (
            not values.get("no_deployed_contract_address")
            and not values.get("quick_check", False)
            and not values.get("deployed_contract_address")
        ):
            raise ValueError("Deployed contract address not provided.")

        if not values.get("no_targets") and not values.get("targets"):
            raise ValueError("Targets not provided.")

        if values.get("incremental") and not values.get("project"):
            raise ValueError(
                "`incremental` config parameter is set to true without specifying `project`."
            )

        if values.get("incremental") and values.get("corpus_target"):
            raise ValueError(
                "Both `incremental` and `corpus_target` are set. Please set only one option."
            )

        if values.get("chain_id") and not values.get("chain_id", "").startswith("0x"):
            raise ValueError(
                f"`chain_id` is not in hex format (0x..). Please provide correct hex value"
            )
        return values


class AnalyzeOptions(BaseSettings):
    solc_version: Optional[str] = Field(
        None, alias="solc-version", env="ANALYZE_SOLC_VERSION"
    )
    remappings: List[str] = []
    scribble_path: str = Field(
        "scribble", alias="scribble-path", env="ANALYZE_SCRIBBLE_PATH"
    )
    no_assert: bool = True
    assert_: bool = Field(alias="assert", default=False, env="ANALYZE_ASSERT")

    def __init__(self, *args, **data: Any):
        try:
            super().__init__(*args, **data)
        except ValidationError as e:
            raise click.exceptions.UsageError(f"Invalid config: {repr_errors(e)}")
        except:
            raise

    class Config:
        env_prefix = "analyze_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        allow_population_by_field_name = True

        @classmethod
        def customise_sources(
            cls,
            init_settings,
            env_settings,
            file_secret_settings,
        ):
            # load in order (from the least priority to the highest priority):
            # 1. config settings from config file
            # 2. .env file
            # 3. environment variables
            # 4. command arguments
            return (
                init_settings,
                env_settings,
                yaml_config_settings_source("analyze"),
                file_secret_settings,
            )
