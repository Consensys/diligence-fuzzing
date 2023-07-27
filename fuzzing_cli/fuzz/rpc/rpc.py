import logging
from typing import Any, Dict, List, Optional, Set, Union

import click
import requests
from requests import RequestException

from fuzzing_cli.fuzz.exceptions import RPCCallError
from fuzzing_cli.fuzz.quickcheck_lib.utils import mk_contract_address
from fuzzing_cli.fuzz.types import EVMBlock, EVMTransaction

from .generic import RPCClientBase

LOGGER = logging.getLogger("fuzzing-cli")

headers = {"Content-Type": "application/json"}
NUM_BLOCKS_UPPER_LIMIT = 9999

SEED_STATE = Dict[str, Any]
CONTRACT_ADDRESS = str
CONTRACT_BYTECODE = str


class RPCClient(RPCClientBase):
    def __init__(self, rpc_url: str, number_of_cores: int = 1):
        self.rpc_url = rpc_url
        self.number_of_cores = number_of_cores

    def call(self, method: str, params: List[Union[str, bool, int, float]]):
        """Make an rpc call to the RPC endpoint

        :return: Result property of the RPC response
        """
        try:
            payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
            response = (
                requests.request("POST", self.rpc_url, headers=headers, json=payload)
            ).json()
            return response.get("result", None)
        except RequestException as e:
            raise RPCCallError(
                f"HTTP error calling RPC method {method} with parameters: {params}"
                f"\nAre you sure the RPC is running at {self.rpc_url}?"
            )

    def get_block(
        self, latest: bool = False, block_number: int = -1
    ) -> Optional[EVMBlock]:
        block_value = "latest" if latest else str(block_number)
        if not latest:
            block_value = hex(block_number)

        block = self.call("eth_getBlockByNumber", [block_value, True])
        return block

    def get_block_by_hash(self, hash: str) -> Optional[EVMBlock]:
        block = self.call("eth_getBlockByHash", [hash, True])
        return block

    def get_code(
        self, contract_address: CONTRACT_ADDRESS
    ) -> Optional[CONTRACT_BYTECODE]:
        deployed_bytecode = self.call("eth_getCode", [contract_address, "latest"])
        if deployed_bytecode == "0x":
            return None
        return deployed_bytecode

    def get_all_blocks(self) -> List[EVMBlock]:
        """Get all blocks from the node running at rpc_url

        Raises an exception if the number of blocks
        exceeds 10000 as it is likely a user error who passed the wrong
        RPC address.
        """
        num_of_blocks = self.get_latest_block_number() + 1
        if num_of_blocks == 0:
            return []

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

    def get_latest_block_number(self) -> int:
        latest_block = self.get_block(latest=True)
        if not latest_block:
            return -1
        num_of_blocks = int(latest_block["number"], 16)
        return num_of_blocks

    def get_transactions(
        self,
        blocks: Optional[List[EVMBlock]] = None,
        block_numbers_to_skip: List[str] = [],
    ) -> List[EVMTransaction]:
        if not blocks:
            blocks = self.get_all_blocks()
        processed_transactions = []
        for block in blocks:
            if block["number"] in block_numbers_to_skip:
                continue
            for transaction in block["transactions"]:
                for key, value in dict(transaction).items():
                    if value is None:
                        transaction[key] = ""
                transaction.update(
                    {
                        "blockCoinbase": block["miner"],
                        "blockDifficulty": block["difficulty"],
                        "blockGasLimit": block["gasLimit"],
                        "blockTimestamp": block["timestamp"],
                    }
                )
                processed_transactions.append(transaction)
        return processed_transactions

    def get_all_deployed_contracts_addresses(
        self, blocks_to_skip: Set[str]
    ) -> List[CONTRACT_ADDRESS]:
        transactions = self.get_transactions(block_numbers_to_skip=list(blocks_to_skip))

        # This is the list of all the contract addresses that are deployed(created)
        # in the rpc(ganache) node.
        contracts = []
        for txn in transactions:
            # If "to" is empty, it means it's a contract creation
            if txn["to"]:
                continue
            # These are contract creation transactions
            contracts.append(
                mk_contract_address(
                    txn["from"][2:], int(txn["nonce"], base=16), prefix=True
                )
            )
        return contracts
