from typing import List, Optional

import click


class FuzzingOptions:
    def __init__(
        self,
        build_directory: str,
        deployed_contract_address: Optional[str] = None,
        target: Optional[List[str]] = None,
        map_to_original_source: bool = False,
        rpc_url: str = "http://localhost:7545",
        faas_url: str = "https://fuzzing-staging.diligence.tools",
        number_of_cores: int = 2,
        campaign_name_prefix: str = "untitled",
        corpus_target: Optional[str] = None,
        additional_contracts_addresses: Optional[List[str]] = None,
        dry_run: bool = False,
        auth_endpoint: str = "https://diligence.us.auth0.com/",
        refresh_token: Optional[str] = None,
        auth_client_id: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.additional_contracts_addresses = additional_contracts_addresses
        self.corpus_target = corpus_target
        self.map_to_original_source = map_to_original_source
        self.dry_run = dry_run
        self.auth_endpoint = auth_endpoint
        self.refresh_token = refresh_token
        self.auth_client_id = auth_client_id
        self.api_key = api_key
        self.build_directory = build_directory
        self.deployed_contract_address = deployed_contract_address
        self.target = target
        self.rpc_url = rpc_url
        self.faas_url = faas_url
        self.number_of_cores = int(number_of_cores)
        self.campaign_name_prefix = campaign_name_prefix
        self.auth_client_id = auth_client_id

        self.validate()

    def validate(self):
        if not self.build_directory:
            raise click.exceptions.UsageError(
                "Build directory not provided. You need to set the `build_directory` "
                "on the `fuzz` key of your .mythx.yml config file."
            )
        if not self.api_key and (
            not self.refresh_token or
            not self.auth_client_id or
            not self.auth_endpoint
        ):
            raise click.exceptions.UsageError(
                "API key or Refresh Token were not provided. You need to provide either an API key or a Refresh Token"
                "as the `--api-key` or `--refresh-token` parameters respectively of the fuzz run command"
                "or set `api_key` or `refresh_token` on the `fuzz` key of your .mythx.yml config file."
            )
        if not self.deployed_contract_address:
            raise click.exceptions.UsageError(
                "Deployed contract address not provided. You need to provide an address as the `--address` "
                "parameter of the fuzz run command.\nYou can also set the `deployed_contract_address`"
                "on the `fuzz` key of your .mythx.yml config file."
            )
        if not self.target:
            raise click.exceptions.UsageError(
                "Target not provided. You need to provide a target as the last parameter of the fuzz run command."
                "\nYou can also set the `targets` on the `fuzz` key of your .mythx.yml config file."
            )
