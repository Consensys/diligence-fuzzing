import json
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import BuildArtifactsError, EmptyArtifactsError
from fuzzing_cli.fuzz.types import Contract, IDEPayload, Source
from fuzzing_cli.util import LOGGER, sol_files_by_directory


class IDEArtifacts(ABC):
    def __init__(
        self,
        options: FuzzingOptions,
        targets: List[str],
        build_dir: Path,
        sources_dir: Path,
        map_to_original_source: bool = False,
    ):
        self._payload: Optional[IDEPayload] = None
        self._options = options
        self.targets = targets
        self.build_dir = build_dir
        self.sources_dir = sources_dir
        self.map_to_original_source = map_to_original_source

        # self._include is an array with all the solidity file paths under the targets
        self._include: List[str] = []
        if targets:
            include = []
            for target in targets:
                include.extend(sol_files_by_directory(target))
            self._include = include

    @classmethod
    @abstractmethod
    def get_name(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def validate_project(cls) -> bool:
        pass

    @property
    @abstractmethod
    def contracts(self) -> List[Contract]:
        """ Returns sources
        sources = {
            "filename": [
                {
                    "bytecode": <>,
                    ...
                    "deployedBytecode": <>
                }
            ]
        }
        """
        pass

    @property
    @abstractmethod
    def sources(self) -> Dict[str, Source]:
        """ Returns sources
        sources = {
            "filename": {
                "ast": <>,
                "source: ""
            }
        }
        """
        pass

    @staticmethod
    @abstractmethod
    def get_default_build_dir() -> Path:
        pass

    @staticmethod
    @abstractmethod
    def get_default_sources_dir() -> Path:
        pass

    @staticmethod
    def _get_build_artifacts(build_dir) -> Dict:
        # _get_build_artifacts goes through each .json build file and extracts the Source file it references
        # A source file may contain several contracts, so it is possible that a given source file
        # will be pointed to by multiple build artifacts
        # build_files_by_source_file is a dictionary where the key is a source file name
        # and the value is an array of build artifacts (contracts)
        build_files_by_source_file = {}

        build_dir = Path(build_dir)

        if not build_dir.is_dir():
            raise BuildArtifactsError("Build directory doesn't exist")

        for child in build_dir.glob("**/*"):
            if not child.is_file():
                continue
            if not child.name.endswith(".json"):
                continue

            if child.name.startswith(
                "."
            ):  # some hidden file (probably created by OS, especially the Mac OS)
                continue

            data = json.loads(child.read_text("utf-8"))

            source_path = data["sourcePath"]

            if source_path not in build_files_by_source_file:
                # initialize the array of contracts with a list
                build_files_by_source_file[source_path] = []

            build_files_by_source_file[source_path].append(data)

        return build_files_by_source_file

    @staticmethod
    def flatten_contracts(contracts: Dict[str, List[Contract]]) -> List[Contract]:
        return [
            c for contracts_for_file in contracts.values() for c in contracts_for_file
        ]

    @staticmethod
    def compare_bytecode(x: str, y: str) -> bool:
        if x.startswith("0x"):
            x = x[2:]
        if y.startswith("0x"):
            y = y[2:]
        return x == y

    def get_contract(self, deployed_bytecode: str) -> Optional[Contract]:
        result_contracts, _ = self.process_artifacts()
        for _, contracts in result_contracts.items():
            for contract in contracts:
                if self.compare_bytecode(
                    deployed_bytecode, contract["deployedBytecode"]
                ):
                    return contract
        return None

    @lru_cache(maxsize=1)
    def fetch_data(self) -> Tuple[List[Contract], Dict[str, Source]]:
        normalized_include = [self.normalize_path(p) for p in self._include]
        _result_contracts, _result_sources = self.process_artifacts()
        result_contracts = {
            k: v
            for k, v in _result_contracts.items()
            if self.normalize_path(k) in normalized_include
        }
        # result_sources = {
        #     k: v
        #     for k, v in _result_sources.items()
        #     if self.normalize_path(k) in normalized_include
        # }
        return self.flatten_contracts(result_contracts), _result_sources

    @abstractmethod
    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        pass

    def normalize_path(self, path: str) -> str:
        if Path(path).is_absolute():
            return path
        _path = str(self.sources_dir.parent.joinpath(path))
        LOGGER.debug(
            f'Normalizing path "{path}" relative to source_dir. Absolute path "{_path}"'
        )
        return _path

    def validate(self) -> None:
        if len(self.sources.keys()) == 0 or len(self.contracts) == 0:
            raise EmptyArtifactsError()
