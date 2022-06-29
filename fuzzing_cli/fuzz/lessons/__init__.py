import json
import logging
import os
from pathlib import Path
from typing import List

from fuzzing_cli.fuzz.config import update_config
from fuzzing_cli.fuzz.exceptions import FuzzingLessonsError
from fuzzing_cli.fuzz.rpc import RPCClient
from fuzzing_cli.fuzz.types import EVMBlock, SeedSequenceTransaction

LOGGER = logging.getLogger("fuzzing-cli")


class FuzzingLessons:

    @staticmethod
    def check_running_lessons(temp_file_path: Path) -> bool:
        return temp_file_path.exists() and temp_file_path.is_file()

    @staticmethod
    def start_lesson(description: str, config_path: Path, rpc_client: RPCClient, temp_file_path: Path = Path(".fuzzing_lessons.json")):
        if FuzzingLessons.check_running_lessons(temp_file_path):
            raise FuzzingLessonsError("Another fuzzing lesson is running")

        number_of_blocks = rpc_client.get_latest_block_number() + 1
        with temp_file_path.open("w") as f:
            json.dump(
                {
                    "numberOfBlocks": number_of_blocks,
                    "description": description,
                    "configFilePath": str(config_path),
                },
                f,
            )

    @staticmethod
    def stop_lesson(rpc_client: RPCClient, temp_file_path: Path = Path(".fuzzing_lessons.json")):
        if not FuzzingLessons.check_running_lessons(temp_file_path):
            raise FuzzingLessonsError("No fuzzing lesson is running")
        with temp_file_path.open("r") as f:
            lesson_data = json.load(f)
        number_of_blocks_at_start = lesson_data["numberOfBlocks"]
        config_path = lesson_data["configFilePath"]

        number_of_blocks_at_stop = rpc_client.get_latest_block_number() + 1
        if number_of_blocks_at_stop == number_of_blocks_at_start:
            LOGGER.warning("No transaction was recorded in this lesson")
        if number_of_blocks_at_start > 0:
            number_of_blocks_at_start -= 1  # not an obvious conversion to index :)

        lesson_blocks: List[EVMBlock] = []
        for i in range(number_of_blocks_at_start, number_of_blocks_at_stop):
            block = rpc_client.get_block(block_number=i)
            if not block:
                continue
            lesson_blocks.append(block)

        seed_seqs = FuzzingLessons.prepare_suggested_seed_sequences(lesson_blocks)
        update_config(config_path, {"fuzz": {"suggested_seed_seqs": seed_seqs}})
        os.remove(temp_file_path)

    @staticmethod
    def prepare_suggested_seed_sequences(
        blocks: List[EVMBlock]
    ) -> List[SeedSequenceTransaction]:
        seed_seqs: List[SeedSequenceTransaction] = []

        for block in blocks:
            for txn in block["transactions"]:
                if not txn["to"]:  # contract creation
                    continue
                seed_seqs.append(
                    {
                        "address": txn["to"],
                        "gasLimit": txn.get("gas", "0x0"),
                        "gasPrice": txn.get("gasPrice", "0x0"),
                        "input": txn.get("input", "0x0"),
                        "origin": txn["from"],
                        "value": txn.get("value", "0x0"),
                        "blockCoinbase": block["miner"],
                        "blockDifficulty": block["difficulty"],
                        "blockGasLimit": block["gasLimit"],
                        "blockNumber": block["number"],
                        "blockTime": block["timestamp"],
                    }
                )

        return seed_seqs

    @staticmethod
    def abort_lesson(temp_file_path: Path = Path(".fuzzing_lessons.json")):
        if not FuzzingLessons.check_running_lessons(temp_file_path):
            raise FuzzingLessonsError("No fuzzing lesson is running")
        os.remove(temp_file_path)
