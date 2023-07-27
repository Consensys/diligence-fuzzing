from pathlib import Path
from typing import Dict, List, Tuple

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.ide import IDEArtifacts
from fuzzing_cli.fuzz.types import Contract, Source
from tests.common import TEST_BYTECODES


class IDEMock(IDEArtifacts):
    def __init__(self, contracts, *args, **kwargs):
        self.__contracts = contracts
        super().__init__(*args, **kwargs)

    @classmethod
    def get_name(cls) -> str:
        return "mock"

    @classmethod
    def validate_project(cls) -> bool:
        return True

    @staticmethod
    def get_default_build_dir() -> Path:
        return Path.cwd()

    @staticmethod
    def get_default_sources_dir() -> Path:
        return Path.cwd()

    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        return self.__contracts, {}


def test_get_contract():
    options = FuzzingOptions(
        key="dGVzdC1jbGllbnQtMTIzOjpleGFtcGxlLXVzLmNvbQ==::2",
        build_directory=str(Path.cwd()),
        quick_check=True,
        targets=["test.sol"],
    )

    contracts = {
        "test.sol": [
            {
                "deployedBytecode": TEST_BYTECODES[0]["bytecode"],
                "contractName": "test-contract-0",
            },
            {
                "deployedBytecode": TEST_BYTECODES[1]["bytecode"],
                "contractName": "test-contract-1",
            },
        ],
        "test1.sol": [
            {
                "deployedBytecode": TEST_BYTECODES[2]["bytecode"],
                "contractName": "test-contract-2",
            },
            {
                "deployedBytecode": TEST_BYTECODES[3]["bytecode"],
                "contractName": "test-contract-3",
            },
        ],
    }
    ide = IDEMock(contracts, options, Path.cwd(), Path.cwd(), [])

    for i in range(4):
        assert (
            ide.get_contract(TEST_BYTECODES[i]["bytecode"])["contractName"]
            == f"test-contract-{i}"
        )

    assert (
        ide.get_contract(
            "6080b895438a64736f6c63430008110033a2646970667358221220b0a8252c11b708b8f4cf63f42561ac7f0ed003b6f69490daa7946833c175b8e664736f6c63430008110033"
        )
        is None
    )
    assert (
        ide.get_contract(
            "6080358221220b0a8252c11b708b8f4cf63f42561ac7f0ed003b6f69490daa79"
        )
        is None
    )
