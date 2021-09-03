from typing import List, Optional


class FuzzingOptions:
    def __init__(
        self,
        build_directory: str,
        deployed_contract_address: Optional[str] = None,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
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
        self.targets = targets
        self.rpc_url = rpc_url
        self.faas_url = faas_url
        self.number_of_cores = number_of_cores
        self.campaign_name_prefix = campaign_name_prefix
        self.auth_client_id = auth_client_id

        self.validate()

    def validate(self):
        if not self.build_directory:
            raise Exception("You should provide `build_directory`")
        if not self.api_key and (
            not self.refresh_token or
            not self.auth_client_id or
            not self.auth_endpoint
        ):
            raise Exception("You should provide either `api_key` or `refresh_token`")
        if not self.target and not self.targets:
            raise Exception("You should provide either `target` or `targets`")
