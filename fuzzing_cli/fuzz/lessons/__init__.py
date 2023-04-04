import json
import logging
from pathlib import Path
from typing import List

from fuzzing_cli.fuzz.exceptions import FuzzingLessonsError
from fuzzing_cli.fuzz.rpc.generic import RPCClientBase
from fuzzing_cli.fuzz.types import EVMBlock
from fuzzing_cli.fuzz.types import FuzzingLessons as FuzzingLessonsStorage
from fuzzing_cli.fuzz.types import RunningLesson, SeedSequenceTransaction

LOGGER = logging.getLogger("fuzzing-cli")


class FuzzingLessons:
    def __init__(self):
        self.temp_file_path: Path = Path(".fuzzing_lessons.json")

    def get_lessons_storage(self) -> FuzzingLessonsStorage:
        if self.temp_file_path.exists() and self.temp_file_path.is_file():
            with self.temp_file_path.open() as f:
                storage = json.load(f)
        else:  # no file
            storage: FuzzingLessonsStorage = {"runningLesson": None, "lessons": []}
        return storage

    def __update_storage(self, storage: FuzzingLessonsStorage):
        with self.temp_file_path.open("w") as f:
            json.dump(storage, f)

    @staticmethod
    def get_lessons():
        cls = FuzzingLessons()
        storage = cls.get_lessons_storage()
        return storage["lessons"]

    @staticmethod
    def check_running_lessons(storage: FuzzingLessonsStorage) -> bool:
        return storage.get("runningLesson", None) is not None

    def start_lesson(self, description: str, rpc_client: RPCClientBase):
        storage = self.get_lessons_storage()
        if FuzzingLessons.check_running_lessons(storage):
            raise FuzzingLessonsError("Another fuzzing lesson is running")

        number_of_blocks = rpc_client.get_latest_block_number() + 1

        running_lesson: RunningLesson = {
            "description": description,
            "numberOfBlocks": number_of_blocks,
        }

        storage["runningLesson"] = running_lesson
        self.__update_storage(storage)

    def stop_lesson(self, rpc_client: RPCClientBase) -> str:
        storage = self.get_lessons_storage()
        if not FuzzingLessons.check_running_lessons(storage):
            raise FuzzingLessonsError("No fuzzing lesson is running")
        lesson_data: RunningLesson = storage["runningLesson"]
        number_of_blocks_at_start = lesson_data["numberOfBlocks"]
        description = lesson_data["description"]

        number_of_blocks_at_stop = rpc_client.get_latest_block_number() + 1
        if number_of_blocks_at_stop == number_of_blocks_at_start:
            LOGGER.warning("No transaction was recorded in this lesson")
        if number_of_blocks_at_start > 0:
            number_of_blocks_at_start -= (
                1  # not an obvious conversion to index. Sorry :(
            )

        lesson_blocks: List[EVMBlock] = []
        for i in range(number_of_blocks_at_start, number_of_blocks_at_stop):
            block = rpc_client.get_block(block_number=i)
            if not block:
                continue
            lesson_blocks.append(block)

        storage["runningLesson"] = None
        storage["lessons"].append(
            {
                "description": description,
                "transactions": FuzzingLessons.prepare_suggested_seed_sequences(
                    lesson_blocks
                ),
            }
        )
        self.__update_storage(storage)

        return description

    @staticmethod
    def prepare_suggested_seed_sequences(
        blocks: List[EVMBlock],
    ) -> List[List[SeedSequenceTransaction]]:
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

        return [seed_seqs]

    def abort_lesson(self) -> str:
        storage = self.get_lessons_storage()
        if not FuzzingLessons.check_running_lessons(storage):
            raise FuzzingLessonsError("No fuzzing lesson is running")

        lesson_data: RunningLesson = storage["runningLesson"]
        storage["runningLesson"] = None
        self.__update_storage(storage)
        description = lesson_data["description"]
        return description
