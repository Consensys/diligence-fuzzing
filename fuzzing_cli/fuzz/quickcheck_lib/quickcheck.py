import logging
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import QuickCheckError
from fuzzing_cli.fuzz.ide import IDEArtifacts
from fuzzing_cli.fuzz.scribble import ScribbleMixin
from fuzzing_cli.fuzz.solidity import SolidityJob
from fuzzing_cli.fuzz.types import Contract, Source
from fuzzing_cli.util import get_content_from_file

from .utils import mk_contract_address

LOGGER = logging.getLogger("fuzzing-cli")

BASE_ADDRESS = "affeaffeaffeaffeaffeaffeaffeaffeaffeaffe"


def annotate_contracts(targets: List[str], scribble_generator_path: str) -> List[Path]:
    LOGGER.debug(
        f"Annotating targets: {str(targets)} using scribble-generator at path: {scribble_generator_path}"
    )
    _targets = [Path(t) for t in targets]
    # for cases when it's complex command. e.g.: npx scribble-generate
    _scribble_generator_path = scribble_generator_path.split(" ")
    command = _scribble_generator_path + ["--targets"] + targets

    annotated_files: List[Path] = []

    try:
        process: subprocess.CompletedProcess = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if process.returncode != 0:
            reason = f"{process.stdout.decode()}\n{process.stderr.decode()}"
            raise QuickCheckError(
                f"QuickCheckError: Annotating failed\nDetail: {reason}"
            )

        for target in _targets:
            if target.is_dir():  # find all annotated contracts
                _changed_files = [x for x in target.rglob("*.sol.sg_original")]
                _files = [f.parent.joinpath(f.stem) for f in _changed_files]
            else:
                orig_file = target.parent.joinpath(f"{target.name}.sg_original")
                if not orig_file.exists():
                    LOGGER.warning(f'Target "{target}" was not annotated')
                    continue
                _files = [target]
            annotated_files.extend(_files)
    except FileNotFoundError:
        raise QuickCheckError(
            f"QuickCheckError: scribble-generator invocation error. Tried executable at {scribble_generator_path}. "
            f"Please make sure `scribble-generator` is installed properly or provide path "
            f"to the executable using `--scribble-generator-path` option to `fuzz auto`"
        )
    except QuickCheckError as e:
        raise e
    except Exception as e:
        LOGGER.error(e)
        raise QuickCheckError(
            f"QuickCheckError: Unhandled Exception\nDetail: {repr(e)}"
        )

    return annotated_files


def prepare_seed_state(
    contracts: List[Contract], number_of_cores: int, corpus_target: Optional[str] = None
) -> Dict[str, any]:
    setup = {
        "steps": [
            {
                "blockHash": "0xf",
                "blockNumber": hex(i + 1),
                "input": c["bytecode"],
                "from": "0xaffeaffeaffeaffeaffeaffeaffeaffeaffeaffe",
                "gas": "0xffffff",
                "gasPrice": "0x0",
                "hash": "0xf",
                "nonce": "0x0",
                "r": "0xf",
                "s": "0xf",
                "to": "",
                "transactionIndex": "0x0",
                "v": "0xf",
                "value": "0x0",
            }
            for i, c in enumerate(contracts)
        ]
    }
    if corpus_target:
        setup["target"] = corpus_target

    return {
        "discovery-probability-threshold": 0.0,
        "assertion-checking-mode": 1,
        "num-cores": number_of_cores,
        "analysis-setup": setup,
    }


class QuickCheck(IDEArtifacts):
    def __init__(
        self,
        options: FuzzingOptions,
        scribble_path: str,
        targets: List[str],
        build_dir: Optional[Path] = None,
        sources_dir: Optional[Path] = None,
        map_to_original_source: bool = False,
        remappings: List[str] = (),
        solc_version: str = None,
        solc_path: Optional[str] = None,
        no_assert: bool = False,
    ):
        super(QuickCheck, self).__init__(
            options,
            Path(build_dir).absolute() if build_dir else Path.cwd().absolute(),
            Path(sources_dir).absolute() if sources_dir else Path.cwd().absolute(),
            targets=targets,
            map_to_original_source=map_to_original_source,
        )
        self.targets = targets
        self.scribble_path = scribble_path
        self.remappings = remappings
        self.solc_version = solc_version
        self.solc_path = solc_path
        self.no_assert = no_assert

    @classmethod
    def get_name(cls) -> str:  # pragma: no cover
        return "QuickCheck"

    @classmethod
    def validate_project(cls) -> bool:  # pragma: no cover
        return True

    @property
    def contracts(self) -> List[Contract]:
        return self.fetch_data()[0]

    @property
    def sources(self) -> Dict[str, Source]:
        return self.fetch_data()[1]

    @staticmethod
    def get_default_build_dir() -> Path:  # pragma: no cover
        return Path().cwd()

    @staticmethod
    def get_default_sources_dir() -> Path:  # pragma: no cover
        return Path().cwd()

    def arm_contracts(self):
        ScribbleMixin.instrument_solc_in_place(
            file_list=self.targets,
            scribble_path=self.scribble_path,
            remappings=self.remappings,
            solc_version=self.solc_version,
            no_assert=self.no_assert,
        )

    def compile_contracts(self):
        contracts = []
        LOGGER.debug(f"Received {len(self.remappings)} import remappings")

        files = [f for f in self.targets if f.endswith(".sol")]

        if not files:
            LOGGER.debug(f"No Solidity files found in targets")
            return contracts

        LOGGER.debug(f"Found Solidity files to process: {', '.join(files)}")

        job = SolidityJob([Path(t) for t in self.targets])

        return job.compile(
            version=self.solc_version,
            solc_path=self.solc_path,
            remappings=self.remappings,
        )

    @staticmethod
    def get_compiler_generated_source_ids(
        source_map: str, sources: List[str]
    ) -> List[int]:
        num_of_sources = len(sources)
        # this method is necessary because compilation artifacts don't have `generatedSources` for deployedBytecode
        # from solidity compiler's output (i.e. `deployedGeneratedSources`)
        sm = source_map.split(";")
        allFileIds = set()
        for c in sm:
            component = c.split(":")
            if len(component) < 3 or component[2] == "":
                continue
            allFileIds.add(component[2])
        return [int(fileId) for fileId in allFileIds if int(fileId) >= num_of_sources]

    @lru_cache(maxsize=1)
    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        self.arm_contracts()
        result: List[Dict[str, any]] = self.compile_contracts()

        result_contracts: Dict[str, List[Contract]] = {}
        result_sources: Dict[str, Source] = {}

        source_paths = {
            str(data["id"]): source
            for source, data in result.get("sources", {}).items()
        }

        for contract_path, contract_data in result.get("contracts", {}).items():
            contract_name, _ = sorted(
                [
                    (c, len(d["evm"]["bytecode"]["object"]))
                    for c, d in contract_data.items()
                ],
                key=lambda x: x[1],  # sort by length of bytecode
            )[
                -1
            ]  # here we select the contract in file with the longest bytecode

            result_contracts[contract_path] = [
                {
                    "sourcePaths": source_paths,
                    "bytecode": contract_data[contract_name]["evm"]["bytecode"][
                        "object"
                    ],
                    "sourceMap": contract_data[contract_name]["evm"]["bytecode"][
                        "sourceMap"
                    ],
                    "deployedBytecode": contract_data[contract_name]["evm"][
                        "deployedBytecode"
                    ]["object"],
                    "deployedSourceMap": contract_data[contract_name]["evm"][
                        "deployedBytecode"
                    ]["sourceMap"],
                    "contractName": contract_name,
                    "mainSourceFile": contract_path,
                    "ignoredSources": self.get_compiler_generated_source_ids(
                        contract_data[contract_name]["evm"]["deployedBytecode"][
                            "sourceMap"
                        ],
                        list(source_paths.values()),
                    ),
                }
            ]

        for source_name, data in result.get("sources", {}).items():
            result_sources[source_name] = {
                "fileIndex": data["id"],
                "source": data["source"],
                "ast": data["ast"],
            }
            if (
                self.map_to_original_source
                and Path(source_name + ".original").is_file()
            ):
                # we check if the current source file has a non instrumented version
                # if it does, we include that one as the source code
                result_sources[source_name]["source"] = get_content_from_file(
                    source_name + ".original"
                )

        return result_contracts, result_sources
