import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

from typing_extensions import TypedDict

from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.util import sol_files_by_directory


class IDEPayload(TypedDict):
    contracts: List[any]
    sources: Dict[str, any]


class Contract(TypedDict):
    sourcePaths: Dict[int, str]
    deployedSourceMap: str
    deployedBytecode: str
    sourceMap: str
    bytecode: str
    contractName: str
    mainSourceFile: str
    ignoredSources: Optional[List[int]]


class Source(TypedDict):
    fileIndex: int
    source: str
    ast: Dict[str, any]


class IDEArtifacts(ABC):
    def __init__(
        self, targets: List[str], build_dir: Path, map_to_original_source: bool = False
    ):
        self._payload: Optional[IDEPayload] = None
        self.targets = targets
        self.build_dir = build_dir
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
    def get_default_build_dir() -> str:
        pass

    @staticmethod
    @abstractmethod
    def get_default_sources_dir() -> str:
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
