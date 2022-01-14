import json
import os
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from typing_extensions import TypedDict

from fuzzing_cli.fuzz.exceptions import BuildArtifactsError


class IDE(Enum):
    BROWNIE = "brownie"
    HARDHAT = "hardhat"
    TRUFFLE = "truffle"
    SOLIDITY = "solidity"


class IDEPayload(TypedDict):
    contracts: List[any]
    sources: Dict[str, any]


class IDEArtifacts(ABC):
    @property
    @abstractmethod
    def contracts(self) -> Dict:
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
    def sources(self) -> Dict:
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
    def _get_build_artifacts(build_dir) -> Dict:
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


class JobBuilder:
    def __init__(self, artifacts: IDEArtifacts):
        self._artifacts = artifacts

    def payload(self):
        sources = self._artifacts.sources
        contracts = [
            c
            for contracts_for_file in self._artifacts.contracts.values()
            for c in contracts_for_file
        ]
        return {"contracts": contracts, "sources": sources}


class IDEJob:
    def __init__(
        self, target: List[str], build_dir: Path, map_to_original_source: bool = False
    ):
        self.target: List[str] = target
        self.build_dir: Path = build_dir
        self.map_to_original_source: bool = map_to_original_source
        self._payload: Optional[IDEPayload] = None

    @abstractmethod
    def process_artifacts(self) -> IDEArtifacts:
        pass

    def __generate_payload(self):
        artifacts = self.process_artifacts()
        sources = artifacts.sources
        contracts = [
            c
            for contracts_for_file in artifacts.contracts.values()
            for c in contracts_for_file
        ]
        return {"contracts": contracts, "sources": sources}

    @property
    def payload(self) -> IDEPayload:
        if not self._payload:
            self._payload = self.__generate_payload()
        return self._payload


def determine_ide() -> IDE:
    root_dir = Path.cwd().absolute()
    files = list(os.walk(root_dir))[0][2]
    if "brownie-config.yaml" in files:
        return IDE.BROWNIE
    if "hardhat.config.ts" in files:
        return IDE.HARDHAT
    if "hardhat.config.js" in files:
        return IDE.HARDHAT
    if "truffle-config.js" in files:
        return IDE.TRUFFLE
    return IDE.SOLIDITY
