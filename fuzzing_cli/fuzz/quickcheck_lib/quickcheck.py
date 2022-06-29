import logging
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.exceptions import QuickCheckError
from fuzzing_cli.fuzz.ide import IDEArtifacts
from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.quickcheck_lib.utils import mk_contract_address
from fuzzing_cli.fuzz.scribble import ScribbleMixin
from fuzzing_cli.fuzz.solidity import SolidityJob
from fuzzing_cli.fuzz.types import Contract, SeedSequenceTransaction, Source
from fuzzing_cli.util import get_content_from_file

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
            raise Exception(f"Annotating failed. Captured output: {reason}")

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
            f"scribble-generator invocation error. Tried executable at {scribble_generator_path}. "
            f"Please make sure `scribble-generator` is installed properly or provide path "
            f"to the executable using `--scribble-generator-path` option to `fuzz auto`"
        )
    except Exception as e:
        LOGGER.error(e)

    return annotated_files


def prepare_seed_state(
    contracts: List[Contract],
    number_of_cores: int,
    suggested_seed_seqs: List[SeedSequenceTransaction],
    corpus_target: Optional[str] = None,
) -> Dict[str, any]:
    accounts = {}
    for idx, contract in enumerate(contracts):
        contract_address = mk_contract_address(BASE_ADDRESS, idx)
        accounts[contract_address] = {
            "nonce": idx,
            "balance": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "code": contract.get("deployedBytecode"),
            "storage": {"0x0": "0x1"},
        }

    setup = {"initial-state": {"accounts": accounts}}
    if corpus_target:
        setup["target"] = corpus_target
    if len(suggested_seed_seqs) > 0:
        setup["suggested-seed-seqs"] = suggested_seed_seqs

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
            targets,
            Path(build_dir).absolute() if build_dir else Path.cwd().absolute(),
            Path(sources_dir).absolute() if sources_dir else Path.cwd().absolute(),
            map_to_original_source,
        )
        self.targets = targets
        self.scribble_path = scribble_path
        self.remappings = remappings
        self.solc_version = solc_version
        self.solc_path = solc_path
        self.no_assert = no_assert

    @classmethod
    def get_name(cls) -> str:
        return "QuickCheck"

    @classmethod
    def validate_project(cls) -> bool:
        return True

    @property
    def contracts(self) -> List[Contract]:
        return self.process()[0]

    @property
    def sources(self) -> Dict[str, Source]:
        return self.process()[1]

    @staticmethod
    def get_default_build_dir() -> str:
        return ""

    @staticmethod
    def get_default_sources_dir() -> str:
        return ""

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

        for file in files:
            job = SolidityJob(Path(file))
            job.generate_payloads(
                version=self.solc_version,
                solc_path=self.solc_path,
                remappings=self.remappings,
                scribble_path=self.scribble_path,
            )
            LOGGER.debug(f"Generating Solidity payload for {file}")
            contracts.extend(job.payloads)
        return contracts

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

    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        pass

    @lru_cache(maxsize=1)
    def process(self) -> Tuple[List[Contract], Dict[str, Source]]:
        self.arm_contracts()
        artifacts: List[Dict[str, any]] = self.compile_contracts()
        # self.restore_contracts(annotated_contracts)
        artifacts_by_source_file: Dict[str, Dict[str, any]] = {}
        for artifact in artifacts:
            # ignore duplicated artifacts for the source file
            artifacts_by_source_file[artifact.get("main_source")] = artifact

        contracts: List[Contract] = []
        sources: Dict[str, Source] = {}

        for source_file, sf_artifacts in artifacts_by_source_file.items():
            contracts.append(
                {
                    "sourcePaths": {
                        i: s for i, s in enumerate(sf_artifacts["source_list"])
                    },
                    "bytecode": sf_artifacts["bytecode"],
                    "sourceMap": sf_artifacts["source_map"],
                    "deployedBytecode": sf_artifacts["deployed_bytecode"],
                    "deployedSourceMap": sf_artifacts["deployed_source_map"],
                    "contractName": sf_artifacts["contract_name"],
                    "mainSourceFile": sf_artifacts["main_source"],
                    "ignoredSources": self.get_compiler_generated_source_ids(
                        sf_artifacts["deployed_source_map"], sf_artifacts["sources"]
                    ),
                }
            )
            for idx, source_name in enumerate(sf_artifacts["source_list"]):
                sources[source_name] = {
                    "fileIndex": idx,
                    "source": sf_artifacts["sources"][source_name]["source"],
                    "ast": sf_artifacts["sources"][source_name]["ast"],
                }
                if (
                    self.map_to_original_source
                    and Path(source_name + ".original").is_file()
                ):
                    # we check if the current source file has a non instrumented version
                    # if it does, we include that one as the source code
                    sources[source_name]["source"] = get_content_from_file(
                        source_name + ".original"
                    )

        return contracts, sources
