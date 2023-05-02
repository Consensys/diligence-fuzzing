import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.ide.generic import IDEArtifacts
from fuzzing_cli.fuzz.types import Contract, Source
from fuzzing_cli.util import get_content_from_file

LOGGER = logging.getLogger("fuzzing-cli")


class FoundryArtifacts(IDEArtifacts):
    add_compilation_hint = True

    def __init__(
        self,
        options: FuzzingOptions,
        build_dir: Path,
        sources_dir: Path,
        targets: Optional[List[str]] = None,
        map_to_original_source: bool = False,
    ):
        super(FoundryArtifacts, self).__init__(
            options, build_dir, sources_dir, targets, map_to_original_source
        )

    @classmethod
    def get_name(cls) -> str:
        return "foundry"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "foundry.toml" in files

    @staticmethod
    def get_default_build_dir() -> Path:
        return Path.cwd().joinpath("out")

    @staticmethod
    def get_default_sources_dir() -> Path:
        return Path.cwd().joinpath("src")

    @classmethod
    def _get_build_info(cls, build_dir) -> Dict:
        build_dir = Path(build_dir)
        if not build_dir.is_dir():
            raise BuildArtifactsError("Build directory doesn't exist")

        error_msg = "build-info directory doesn't exist."
        if cls.add_compilation_hint:
            error_msg += (
                " Please make sure to run `forge build --build-info` before fuzzing"
            )

        build_info_dir = Path(build_dir).joinpath("build-info")

        if not build_info_dir.is_dir():
            raise BuildArtifactsError(error_msg)

        build_data = {
            "input": {"sources": {}},
            "output": {"sources": {}, "contracts": {}},
        }

        for child in build_info_dir.glob("*.json"):
            if not child.is_file():
                continue

            if child.name.startswith(
                "."
            ):  # some hidden file (probably created by OS, especially the Mac OS)
                continue

            data: Dict[str, Any] = json.loads(child.read_text("utf-8"))

            if (
                data.get("output")
                and data["output"].get("sources") is not None
                and data["output"].get("contracts") is not None
            ):
                build_data["input"]["sources"].update(data["input"]["sources"])
                build_data["output"]["sources"].update(data["output"]["sources"])
                build_data["output"]["contracts"].update(data["output"]["contracts"])

        return build_data

    def get_source(self, source_path: str, sources: Dict[str, Dict[str, str]]) -> str:
        if (
            self.map_to_original_source
            and Path(self.normalize_path(source_path) + ".original").is_file()
        ):
            return get_content_from_file(self.normalize_path(source_path) + ".original")
        return sources[source_path]["content"]

    @lru_cache(maxsize=1)
    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        build_info = self._get_build_info(self.build_dir)

        result_contracts = {}
        result_sources = {}

        source_ids: List[int] = []
        source_paths = {}

        for source_name, source in build_info["output"]["sources"].items():
            source_ids.append(source["id"])
            source_paths[str(source["id"])] = source_name
            result_sources[source_name] = {
                "fileIndex": source["id"],
                "source": self.get_source(source_name, build_info["input"]["sources"]),
                "ast": source["ast"],
            }

        for source_file, contracts in build_info["output"]["contracts"].items():
            result_contracts[source_file] = []
            for contract_name, contract in contracts.items():
                try:
                    result_contracts[source_file] += [
                        {
                            "sourcePaths": self.get_used_sources(
                                source_paths,
                                contract["evm"]["deployedBytecode"]["sourceMap"],
                            ),
                            "deployedSourceMap": contract["evm"]["deployedBytecode"][
                                "sourceMap"
                            ],
                            "deployedBytecode": contract["evm"]["deployedBytecode"][
                                "object"
                            ],
                            "sourceMap": contract["evm"]["bytecode"]["sourceMap"],
                            "bytecode": contract["evm"]["bytecode"]["object"],
                            "contractName": contract_name,
                            "mainSourceFile": source_file,
                            "ignoredSources": self.get_ignored_sources(
                                generated_sources=contract["evm"][
                                    "deployedBytecode"
                                ].get("generatedSources"),
                                source_map=contract["evm"]["deployedBytecode"][
                                    "sourceMap"
                                ],
                                source_ids=source_ids,
                            ),
                        }
                    ]
                except KeyError as e:
                    raise BuildArtifactsError(
                        f"Build artifact did not contain expected key. Contract: {contract}: \n{e}"
                    )

        return result_contracts, result_sources
