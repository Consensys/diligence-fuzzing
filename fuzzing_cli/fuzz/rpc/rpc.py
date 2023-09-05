import json
import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Union

import click
import requests
from requests import RequestException

from fuzzing_cli.fuzz.exceptions import RPCCallError
from fuzzing_cli.fuzz.quickcheck_lib.utils import mk_contract_address
from fuzzing_cli.fuzz.types import DebugTraceResult, EVMBlock, EVMTransaction, StructLog

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

    @staticmethod
    def parse_rpc_node_kind(rpc_node_info: Optional[str]) -> Optional[str]:
        if not rpc_node_info:
            return None
        rpc_node_info_parsed = rpc_node_info.split("/")
        kind = "unknown"
        if len(rpc_node_info_parsed) > 0:
            kind_raw = rpc_node_info_parsed[0].lower()
            if "ganache" in kind_raw:
                kind = "ganache"
            elif "hardhat" in kind_raw:
                kind = "hardhat"
            elif "anvil" in kind_raw:
                kind = "anvil"
            else:
                kind = kind_raw

        return kind

    @lru_cache(maxsize=1)
    def get_rpc_node_info(self) -> Dict[str, Any]:
        """Get information about the RPC node"""
        try:
            version = self.call("web3_clientVersion", [])
        except RPCCallError:
            version = None
        return {"kind": self.parse_rpc_node_kind(version), "version": version}

    def call(self, method: str, params: List[Union[str, bool, int, float]]):
        """Make an rpc call to the RPC endpoint

        :return: Result property of the RPC response
        """
        try:
            payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
            response = (
                requests.request("POST", self.rpc_url, headers=headers, json=payload)
            ).json()
            result = response.get("result", None)
            if result is None and response.get("error"):
                LOGGER.debug(f"RPC call error: {json.dumps(response['error'])}")
            return result
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

    def get_internally_created_contracts(self, transaction_hash: str) -> List[str]:
        trace: Optional[DebugTraceResult] = self.call(
            "debug_traceTransaction", [transaction_hash]
        )
        if trace is None:
            return []

        if not trace.get("structLogs", []):
            warning_message = "No structLogs found in debug_traceTransaction response"
            rpc_node_info = self.get_rpc_node_info()
            if rpc_node_info["kind"] == "anvil":
                warning_message += (
                    "\nPlease start anvil node with --steps-tracing option (i.e. `anvil --steps-tracing`) "
                    "for fuzzing cli to detect internal contract creations automatically"
                )
            warning_message += f"\nRPC node version is \"{rpc_node_info['version']}\""
            LOGGER.warning(warning_message)
            return []

        # arrange structLogs by depth and pc (program counter)
        struct_logs: Dict[int, Dict[int, StructLog]] = {}
        for entry in trace.get("structLogs", []):
            depth = entry["depth"]
            pc = entry["pc"]
            if depth not in struct_logs:
                struct_logs[depth] = {}
            struct_logs[depth][pc] = entry

        contracts = []

        for depth, struct_logs_by_pc in struct_logs.items():
            for pc, struct_log in struct_logs_by_pc.items():
                op = struct_log["op"].lower()
                if op != "create" and op != "create2":
                    # skip non-create operations
                    continue
                if struct_log.get("error"):
                    LOGGER.debug(
                        f"Skipping failed contract creation in transaction {transaction_hash}. "
                        f"Struct Log: {json.dumps(struct_log)}"
                    )
                    # skip failed contract creations
                    continue

                next_op = struct_logs_by_pc.get(pc + 1)
                if next_op is None:
                    # skip contract creations without subsequent operations
                    LOGGER.debug(
                        f"Skipping contract creation without subsequent operations in "
                        f"transaction {transaction_hash}. Struct Log: {json.dumps(struct_log)}"
                    )
                    continue
                # the result of create or create2 operation is the newly created contract's address. The address
                # will be the top-most element on the stack. So, we need to get the next operation's
                # (with pc counter + 1 and at the same depth) stack and get the last element from the stack array,
                # which corresponds to the stack top.
                # Note: some RPC nodes return the stack elements as a 256-bit hex string (64 characters)
                # padded with 0s at the beginning, while others return it as a 160-bit hex string (40 characters). So,
                # we need to get the last 40 characters from the stack element.
                contract_address = next_op["stack"][-1][-40:]
                LOGGER.debug(
                    f"Found newly deployed contract in transaction {transaction_hash}. "
                    f"Address: {contract_address}"
                )
                contracts.append(f"0x{contract_address}")

        return contracts

    def get_all_deployed_contracts_addresses(
        self, blocks_to_skip: Set[str]
    ) -> List[CONTRACT_ADDRESS]:
        transactions = self.get_transactions(block_numbers_to_skip=list(blocks_to_skip))

        # This is the list of all the contract addresses that are deployed(created)
        # in the rpc node.
        contracts = []
        for txn in transactions:
            if not txn["to"]:
                # this is a contract creation transaction (with "to" set to null)
                contracts.append(
                    mk_contract_address(
                        txn["from"][2:], int(txn["nonce"], base=16), prefix=True
                    )
                )
                continue
            # this is not an obvious contract creation transaction, but another contracts could be deployed
            # in an internal transactions (e.g. Factory pattern, where a contract creates
            # another contract in some method).
            contracts.extend(
                self.get_internally_created_contracts(txn["hash"]),
            )

        return contracts
