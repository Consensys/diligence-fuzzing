import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from fuzzing_cli.fuzz.scribble import ScribbleMixin
from solidity import SolidityJob

PRAGMA_PATTERN = r"pragma solidity [\^<>=]*(\d+\.\d+\.\d+);"
RGLOB_BLACKLIST = ["node_modules"]
LOGGER = logging.getLogger("fuzzing-cli")


class QuickCheck:
    def __init__(self,
        targets: List[str],
        scribble_path: str,
        remappings: Tuple[str] = (),
        solc_version: str = None,
        solc_path: Optional[str] = None,
        no_assert: bool = False,
        scribble_generator_path: str = "npx scribble-generate",
    ):
        self.targets = targets
        self.scribble_path = scribble_path
        self.remappings = remappings
        self.solc_version = solc_version
        self.solc_path = solc_path
        self.no_assert = no_assert
        self.scribble_generator_path = scribble_generator_path

    def annotate_contracts(self) -> List[Path]:
        command = [self.scribble_generator_path]
        annotated_files: List[Path] = []
        for target in self.targets:
            _target = Path(target)
            if _target.is_dir():
                process = subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=_target,
                )
            else:
                process = subprocess.run(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=_target.parent.absolute(),
                )
            if process.returncode == 0:
                if _target.is_dir():  # find all annotated contracts
                    _changed_files = [x for x in _target.rglob("*.orig.sol")]
                    _files = [
                        _target.parent.joinpath(
                            ".".join(f.name.split(".")[:-2] + ["sol"]),
                        )
                        for f in _changed_files
                    ]
                else:
                    orig_file = _target.parent.joinpath(".".join(_target.name.split(".")[:-1] + ["orig", "sol"]))
                    if not orig_file.exists():
                        LOGGER.warning(f"File {_target} was not annotated")
                        continue
                    _files = [_target]
                annotated_files.extend(_files)
            else:
                # handle error
                pass

        return annotated_files

    def restore_contracts(self, files: List[Path]):
        for f in files:
            orig_file = f.parent.joinpath(".".join(f.name.split(".")[:-1] + ["orig", "sol"]))
            orig_file.replace(f)

    def arm_contracts(self, targets: List[str]):
        ScribbleMixin.instrument_solc_in_place(
            file_list=self.targets,
            scribble_path=self.,
            remappings=self.remappings,
            solc_version=self.solc_version,
            no_assert=self.no_assert,
        )

    def compile_contracts(self, targets: List[str]):
        contracts = []
        LOGGER.debug(f"Received {len(self.remappings)} import remappings")

        files = [f for f in targets if f.endswith(".sol")]

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


    def process(self):
        annotated_contracts = self.annotate_contracts()
        targets = [str(c) for c in annotated_contracts]
        self.arm_contracts(targets)
        contracts = self.compile_contracts(targets)
        self.restore_contracts(annotated_contracts)
        return contracts

