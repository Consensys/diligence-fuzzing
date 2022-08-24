from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.ide import IDEArtifacts
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

    @abstractmethod
    def validate_seed_state(
        self, seed_state: Dict[str, any]
    ) -> Tuple[Dict[str, str], List[str]]:  # pragma: no cover
        ...

    @abstractmethod
    def get_seed_state(
        self,
        address: str,
        other_addresses: Optional[List[str]],
        corpus_target: Optional[str] = None,
    ) -> Dict[str, any]:  # pragma: no cover
        ...

    @staticmethod
    @abstractmethod
    def path_inclusion_checker(paths: List[str]):  # pragma: no cover
        ...

    @abstractmethod
    def check_contracts(
        self,
        seed_state: Dict[str, any],
        artifacts: IDEArtifacts,
        source_targets: List[str],
    ):  # pragma: no cover
        ...
