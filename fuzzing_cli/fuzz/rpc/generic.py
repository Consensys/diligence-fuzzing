from abc import ABC, abstractmethod
from typing import List, Optional

from fuzzing_cli.fuzz.types import EVMBlock, EVMTransaction


class RPCClientBase(ABC):
    @abstractmethod
    def get_block(
        self, latest: bool = False, block_number: int = -1
    ) -> Optional[EVMBlock]:  # pragma: no cover
        ...

    @abstractmethod
    def get_block_by_hash(self, _hash: str) -> Optional[EVMBlock]:  # pragma: no cover
        ...

    @abstractmethod
    def get_code(self, contract_address: str) -> Optional[str]:  # pragma: no cover
        ...

    @abstractmethod
    def get_all_blocks(self) -> List[EVMBlock]:  # pragma: no cover
        ...

    @abstractmethod
    def get_latest_block_number(self) -> int:  # pragma: no cover
        ...

    @abstractmethod
    def get_transactions(
        self,
        blocks: Optional[List[EVMBlock]] = None,
        block_numbers_to_skip: List[str] = [],
    ) -> List[EVMTransaction]:  # pragma: no cover
        ...
