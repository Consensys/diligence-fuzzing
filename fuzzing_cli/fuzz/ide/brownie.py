import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.ide.generic import IDEArtifacts
from fuzzing_cli.fuzz.types import Contract, Source
from fuzzing_cli.util import get_content_from_file

LOGGER = logging.getLogger("fuzzing-cli")


class BrownieArtifacts(IDEArtifacts):
    def __init__(
        self,
        options: FuzzingOptions,
        build_dir: Path,
        sources_dir: Path,
        targets: Optional[List[str]] = None,
        map_to_original_source: bool = False,
    ):
        super(BrownieArtifacts, self).__init__(
            options, build_dir, sources_dir, targets, map_to_original_source
        )

    @classmethod
    def get_name(cls) -> str:
        return "brownie"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "brownie-config.yaml" in files

    @staticmethod
    def get_default_build_dir() -> Path:
        return Path.cwd().joinpath("build/contracts")

    @staticmethod
    def get_default_sources_dir() -> Path:
        return Path.cwd().joinpath("contracts")

    @lru_cache(maxsize=1)
    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        """example build_files_by_source_file
        {
            'contracts/Token.sol':
                {
                    'abi':... ,
                    'ast':... ,
                    'source':...,
                    ''
                }
        }
        """
        build_files_by_source_file = self._get_build_artifacts(self.build_dir)
        result_contracts = {}
        result_sources = {}

        source_ids: List[int] = []

        for source_file, contracts in build_files_by_source_file.items():
            for contract in contracts:
                for file_index, source_file_dep in contract["allSourcePaths"].items():
                    if source_file_dep in result_sources.keys():
                        continue

                    if source_file_dep not in build_files_by_source_file:
                        LOGGER.debug(f"{source_file} not found.")
                        continue

                    # We can select any dict on the build_files_by_source_file[source_file] array
                    # because the .source and .ast values will be the same in all
                    file_index = int(file_index)
                    target_file = build_files_by_source_file[source_file_dep][0]
                    result_sources[source_file_dep] = {
                        "fileIndex": file_index,
                        "source": target_file["source"],
                        "ast": target_file["ast"],
                    }
                    source_ids.append(file_index)

                    if (
                        self.map_to_original_source
                        and Path(source_file_dep + ".original").is_file()
                    ):
                        # we check if the current source file has a non instrumented version
                        # if it does, we include that one as the source code
                        result_sources[source_file_dep][
                            "source"
                        ] = get_content_from_file(source_file_dep + ".original")

        # ( 'contracts/Token.sol', {'allSourcePaths':..., 'deployedSourceMap': ... } )
        for source_file, contracts in build_files_by_source_file.items():
            result_contracts[source_file] = []
            for contract in contracts:
                # We get the build items from brownie and rename them into the properties used by the FaaS
                try:
                    result_contracts[source_file] += [
                        {
                            "sourcePaths": contract["allSourcePaths"],
                            "deployedSourceMap": contract["deployedSourceMap"],
                            "deployedBytecode": contract["deployedBytecode"],
                            "sourceMap": contract["sourceMap"],
                            "bytecode": contract["bytecode"],
                            "contractName": contract["contractName"],
                            "mainSourceFile": contract["sourcePath"],
                            "ignoredSources": self.get_ignored_sources(
                                generated_sources=None,
                                source_map=contract["deployedSourceMap"],
                                source_ids=source_ids,
                            ),
                        }
                    ]
                except KeyError as e:
                    raise BuildArtifactsError(
                        f"Build artifact did not contain expected key. Contract: {contract}: \n{e}"
                    )
        return result_contracts, result_sources
