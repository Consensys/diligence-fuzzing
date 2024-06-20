import json
import logging
import os
import random
import string
from typing import Dict
from urllib.parse import urljoin

import requests
from requests.structures import CaseInsensitiveDict

from fuzzing_cli.fuzz.scribble import ScribbleMixin

from .config import AuthHandler, FuzzingOptions
from .exceptions import BadStatusCode, RequestError, ScribbleMetaError
from .ide.generic import IDEArtifacts

LOGGER = logging.getLogger("fuzzing-cli")


class FaasClient:
    """A client to interact with the FaaS API.

    This object receives solidity compilation artifacts and a Harvey Seed state, generates a payload that the faas
    API can consume and submits it, also triggering the start of a Campaign.
    """

    def __init__(
        self, options: FuzzingOptions, project_type: str, auth_handler: AuthHandler
    ):
        self.options = options
        self.project_type = project_type
        self.auth_handler = auth_handler

    @property
    def headers(self):
        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = f"Bearer {self.auth_handler.api_key}"
        return headers

    def generate_campaign_name(self):
        """Return a random name with the provided prefix self.campaign_name_prefix."""
        letters = string.ascii_lowercase
        random_string = "".join(random.choice(letters) for _ in range(5))
        return str(self.options.campaign_name_prefix + "_" + random_string)

    def start_faas_campaign(self, payload):
        """Make HTTP request to the faas"""
        try:
            req_url = urljoin(
                self.options.faas_url, "api/campaigns/?start_immediately=true"
            )
            response_status_code = -1
            response = requests.post(req_url, json=payload, headers=self.headers)
            # We need to store the response status code before we call response.json() because .json() may raise an exception
            # and we want to be able to access the status code in the exception handler to handle the 502s.
            response_status_code = response.status_code
            response_data = response.json()
            if response.status_code != requests.codes.ok:
                if (
                    response.status_code == 403
                    and response_data["detail"]
                    and response_data["error"]
                    in ("SubscriptionError", "FuzzingLimitReachedError")
                ):
                    msg = response_data["error"]
                    if response_data["error"] == "SubscriptionError":
                        msg = "Subscription Error"
                    elif response_data["error"] == "FuzzingLimitReachedError":
                        msg = "Fuzzing Limit Reached Error"
                    raise BadStatusCode(msg, response_data["detail"])

                raise BadStatusCode(
                    f"Got http status code {response.status_code} for request {req_url}",
                    detail=response_data["detail"],
                )
            return response_data["id"]
        except Exception as e:
            if response_status_code == 502:
                # This is just a hotfix for the 502 error, which we think is caused by the payload being too large. However,the campaign is still
                # created, just not started. Even stranger, upon a second request, the campaign is started. So there might be caching involved.
                raise RequestError(
                    "Error starting FaaS campaign. If the issue persists, contact support at support@fuzzing.zendesk.com or use the widget on https://fuzzing.diligence.tools .",
                    detail="Server side error, it is possible that the campaign payload is too large.",
                )
            if isinstance(e, BadStatusCode):
                raise e
            raise RequestError(
                "Error starting FaaS campaign. If the issue persists, contact support at support@fuzzing.zendesk.com or use the widget on https://fuzzing.diligence.tools .",
                detail=repr(e),
            )

    def create_faas_campaign(
        self, campaign_data: IDEArtifacts, seed_state: Dict[str, any]
    ):
        """Submit a campaign to the FaaS and start that campaign.

        This function takes a FaaS payload and makes an HTTP request to the Faas backend, which
        then creates and starts a campaign. The campaign is started because of the `start_immediately=true` query
        parameter.

        This will send the following data to the FaaS for analysis:

        * :code:`name`
        * :code:`parameters` A dict of Harvey configuration options
        * :code:`sources` A dict containing source files code and AST
        * :code:`contracts` Solidity artifacts of the target smart contracts
        * :code:`corpus` Seed state of the target contract. Usually the list of transactions that took place on the
        local ganache (or equivalent) instance.

        :return: Campaign ID
        """
        api_payload = {
            "parameters": {
                "discovery-probability-threshold": seed_state[
                    "discovery-probability-threshold"
                ],
                "num-cores": seed_state["num-cores"],
                "assertion-checking-mode": seed_state["assertion-checking-mode"],
            },
            "name": self.generate_campaign_name(),
            "corpus": seed_state["analysis-setup"],
            "sources": campaign_data.sources,
            "contracts": campaign_data.contracts,
            "quickCheck": self.options.quick_check,
            "mapToOriginalSource": self.options.map_to_original_source,
        }

        if self.options.project is not None:
            api_payload["project"] = self.options.project

        if self.options.time_limit is not None:
            api_payload["timeLimit"] = self.options.time_limit

        if self.options.chain_id is not None:
            api_payload["parameters"]["chain-id"] = self.options.chain_id

        if self.options.enable_cheat_codes is not None:
            api_payload["parameters"][
                "enable-cheat-codes"
            ] = self.options.enable_cheat_codes

        if self.options.foundry_tests:
            # force enable cheat codes for foundry tests
            api_payload["parameters"]["enable-cheat-codes"] = True
            api_payload["foundryTests"] = True
            if self.options.foundry_tests_list is not None:
                api_payload["foundryTestsList"] = self.options.foundry_tests_list

        if self.options.max_sequence_length is not None:
            api_payload["parameters"][
                "max-sequence-length"
            ] = self.options.max_sequence_length

        if self.options.ignore_code_hash is not None:
            api_payload["parameters"][
                "ignore-code-hash"
            ] = self.options.ignore_code_hash

        try:
            instr_meta = ScribbleMixin.get_arming_instr_meta()
            if instr_meta is not None:
                api_payload["instrumentationMetadata"] = instr_meta
        except Exception as e:
            raise ScribbleMetaError(
                "Error getting Scribble arming metadata", detail=repr(e)
            )

        if self.options.dry_run:  # pragma: no cover
            # if the env var FUZZ_DRY_RUN_NO_PRINT is set, don't print the payload
            if os.environ.get("FUZZ_DRY_RUN_NO_PRINT") is None:
                if self.options.dry_run_output is not None:
                    with open(self.options.dry_run_output, "w") as f:
                        f.write(json.dumps(api_payload, indent=4))
                    print(
                        f"Dry run output written to file {self.options.dry_run_output}"
                    )
                else:
                    print(json.dumps(api_payload, indent=4))
            else:
                print("Dry run enabled, not printing payload.")
            return "campaign not started due to --dry-run option"

        campaign_id = self.start_faas_campaign(api_payload)

        return campaign_id
