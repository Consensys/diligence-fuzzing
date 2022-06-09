import logging
from typing import Dict, List, Optional, Tuple, TypedDict

import click
import requests
from click import ClickException, UsageError
from requests import RequestException

from .exceptions import FaaSError, RPCCallError
from .ide import IDEArtifacts
from .quickcheck_lib.utils import mk_contract_address

LOGGER = logging.getLogger("fuzzing-cli")

headers = {"Content-Type": "application/json"}
NUM_BLOCKS_UPPER_LIMIT = 9999

EVMTransaction = TypedDict(
    "EVMTransaction",
    {
        "hash": str,
        "nonce": str,
        "blockHash": str,
        "blockNumber": str,
        "transactionIndex": str,
        "from": str,
        "to": str,
        "value": str,
        "gas": str,
        "gasPrice": str,
        "input": str,
        "v": str,
        "r": str,
        "s": str,
    },
)


class MissingTargetsError(FaaSError):
    pass


class TargetsNotFoundError(FaaSError):
    pass


class RPCClient:
    def __init__(self, rpc_url: str, number_of_cores: int):
        self.rpc_url = rpc_url
        self.number_of_cores = number_of_cores

    def call(self, method: str, params: str):
        """Make an rpc call to the RPC endpoint

        :return: Result property of the RPC response
        """
        try:
            payload = (
                '{"jsonrpc":"2.0","method":"'
                + method
                + '","params":'
                + params
                + ',"id":1}'
            )
            response = (
                requests.request("POST", self.rpc_url, headers=headers, data=payload)
            ).json()
            return response["result"]
        except RequestException as e:
            raise RPCCallError(
                f"HTTP error calling RPC method {method} with parameters: {params}"
                f"\nAre you sure the RPC is running at {self.rpc_url}?"
            )

    def get_block(self, latest: bool = False, block_number: int = -1):
        block_value = "latest" if latest else str(block_number)
        if not latest:
            block_value = hex(block_number)

        block = self.call("eth_getBlockByNumber", '["' + block_value + '", true]')
        return block

    def get_code(self, contract_address: str) -> Optional[str]:
        deployed_bytecode = self.call(
            "eth_getCode", f'["{contract_address}", "latest"]'
        )
        if deployed_bytecode == "0x":
            return None
        return deployed_bytecode

    def get_all_blocks(self):
        """ Get all blocks from the node running at rpc_url

        Raises an exception if the number of blocks
        exceeds 10000 as it is likely a user error who passed the wrong
        RPC address.
        """
        latest_block = self.get_block(latest=True)
        if not latest_block:
            return []

        num_of_blocks = int(latest_block["number"], 16) + 1
        if num_of_blocks > NUM_BLOCKS_UPPER_LIMIT:
            raise click.exceptions.ClickException(
                "Number of blocks existing on the ethereum node running at "
                + str(self.rpc_url)
                + " can not exceed 10000. Did you pass the correct RPC url?"
            )
        blocks = []
        for i in range(0, num_of_blocks):
            blocks.append(self.get_block(block_number=i))
        return blocks

    def validate_seed_state(
        self, seed_state: Dict[str, any]
    ) -> Tuple[Dict[str, str], List[str]]:
        steps: List[EVMTransaction] = seed_state["analysis-setup"]["steps"]
        contracts: List[str] = []
        for txn in steps:
            if txn["to"]:
                continue
            contracts.append(
                mk_contract_address(
                    txn["from"][2:], int(txn["nonce"], base=16), prefix=True
                )
            )

        unknown_targets = []

        targets: List[str] = [seed_state["analysis-setup"]["address-under-test"]] + (
            seed_state["analysis-setup"].get("other-addresses-under-test", []) or []
        )
        targets = [t.lower() for t in targets]

        for target in targets:
            if target.lower() not in contracts:
                unknown_targets.append(target)

        missing_targets: Dict[str, str] = {}
        for contract in contracts:
            if contract not in targets:
                missing_targets[contract] = self.get_code(contract)

        return missing_targets, unknown_targets

    def get_seed_state(
        self,
        address: str,
        other_addresses: Optional[List[str]],
        corpus_target: Optional[str] = None,
    ) -> Dict[str, any]:
        try:
            blocks = self.get_all_blocks()
            processed_transactions = []
            for block in blocks:
                for transaction in block["transactions"]:
                    for key, value in dict(transaction).items():
                        if value is None:
                            transaction[key] = ""
                    processed_transactions.append(transaction)

            if len(processed_transactions) == 0:
                raise click.exceptions.UsageError(
                    f"Unable to generate the seed state for address {address}. "
                    f"No transactions were found in an ethereum node running at {self.rpc_url}"
                )

            setup = dict(
                {
                    "address-under-test": address,
                    "steps": processed_transactions,
                    "other-addresses-under-test": other_addresses,
                }
            )
            """Get a seed state for the target contract to be used by Harvey"""
            if corpus_target:
                setup["target"] = corpus_target
            return {
                "discovery-probability-threshold": 0.0,
                "assertion-checking-mode": 1,
                "num-cores": self.number_of_cores,
                "analysis-setup": setup,
            }

        except ClickException:
            raise
        except Exception as e:
            LOGGER.warning(f"Could not generate seed state for address: {address}")
            raise click.exceptions.UsageError(
                (
                    "Unable to generate the seed state for address "
                    + str(address)
                    + ". Are you sure you passed the correct contract address?"
                )
            ) from e

    def check_contracts(
        self,
        seed_state: Dict[str, any],
        artifacts: IDEArtifacts,
        source_targets: List[str],
    ):
        try:
            missing_targets, unknown_targets = self.validate_seed_state(seed_state)

            if unknown_targets:
                raise ClickException(
                    f"Unable to find contracts deployed at {', '.join(unknown_targets)}"
                )

            missing_targets_resolved: List[
                Tuple[str, Optional[str], Optional[str]]
            ] = []
            for address, deployed_bytecode in missing_targets.items():
                if deployed_bytecode is None:
                    contract = None
                else:
                    contract = artifacts.get_contract(deployed_bytecode)
                missing_targets_resolved.append(
                    (
                        address,
                        contract.get("mainSourceFile", "null") if contract else "null",
                        contract.get("contractName", "null") if contract else "null",
                    )
                )

            mismatched_targets: List[Tuple[str, str]] = []
            for t in missing_targets_resolved:
                source_file = t[1]
                if source_file == "null":
                    continue
                if source_file in source_targets:
                    mismatched_targets.append((source_file, t[0]))

            if mismatched_targets:
                data = "\n".join(
                    [f"  ◦ Target: {t} Address: {a}" for t, a in mismatched_targets]
                )
                raise ClickException(
                    f"Following targets were provided without setting up "
                    f"their addresses in the config file or as parameters to `fuzz run`:\n{data}"
                )

            if missing_targets_resolved:
                data = "\n".join(
                    [
                        f"  ◦ Address: {t[0]} Source File: {t[1]} Contract Name: {t[2]}"
                        for t in missing_targets_resolved
                    ]
                )
                click.secho(
                    f"⚠️ Following contracts were not included into the seed state:\n{data}"
                )

            contract_targets: List[str] = [
                seed_state["analysis-setup"]["address-under-test"]
            ] + (
                seed_state["analysis-setup"].get("other-addresses-under-test", []) or []
            )
            contract_targets = [t.lower() for t in contract_targets]
            dangling_contract_targets: List[Tuple[Optional[str], str]] = []
            for t in contract_targets:
                # correlate to the source file
                deployed_bytecode = self.get_code(t)
                if deployed_bytecode is None:  # it's unknown contract
                    dangling_contract_targets.append((None, t))
                    continue
                contract = artifacts.get_contract(deployed_bytecode)
                if (
                    not contract
                    or contract.get("mainSourceFile", None) is None
                    or contract["mainSourceFile"] not in source_targets
                ):
                    dangling_contract_targets.append(
                        (contract.get("mainSourceFile", None) if contract else None, t)
                    )

            if dangling_contract_targets:
                data = "\n".join(
                    [
                        f"  ◦ Address: {a} Target: {t}"
                        for t, a in dangling_contract_targets
                    ]
                )
                raise ClickException(
                    f"Following contract's addresses were provided without specifying them as "
                    f"a target prior to `fuzz run`:\n{data}"
                )

        except RPCCallError as e:
            raise UsageError(f"{e}")
        except:
            raise
