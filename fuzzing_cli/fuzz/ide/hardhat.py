import json
import os
from collections import defaultdict
from functools import lru_cache, partial
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from fuzzing_cli.fuzz.analytics import Session
from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.types import Contract, Source
from fuzzing_cli.util import get_content_from_file

from . import IDEArtifacts


class HardhatArtifacts(IDEArtifacts):
    add_compilation_hint = False

    def __init__(
        self,
        options,
        build_dir: Path,
        sources_dir: Path,
        targets: Optional[List[str]] = None,
        map_to_original_source: bool = False,
    ):
        super().__init__(
            options, build_dir, sources_dir, targets, map_to_original_source
        )
        self._unlinked_libraries: List[Tuple[Contract, Dict[str, Set[str]]]] = []

    @classmethod
    def get_name(cls) -> str:
        return "hardhat"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "hardhat.config.ts" in files or "hardhat.config.js" in files

    @staticmethod
    def get_default_build_dir() -> Path:
        return Path.cwd().joinpath("artifacts")

    @staticmethod
    def get_default_sources_dir() -> Path:
        return Path.cwd().joinpath("contracts")

    def _get_build_info(self, build_dir: Path) -> Dict[str, Dict[str, Path]]:
        if not build_dir.is_dir():
            raise BuildArtifactsError("Build directory doesn't exist")

        # Here we need to resolve sources_dir relative to build_dir's parent
        # because sources_dir can be provided as a relative or an absolute path deeply nested
        # in the sources directory (which is `contracts` by default in Hardhat), and we need to
        # resolve it to the same level as build_dir, because Hardhat stores build artifacts
        # in the `artifacts` directory which is at the same level as the `contracts` directory
        built_contracts = build_dir.joinpath(
            self.sources_dir.relative_to(build_dir.parent)
        )

        result = defaultdict(dict)

        for child in built_contracts.glob("**/*.dbg.json"):
            if not child.is_file():
                continue

            if child.name.startswith(
                "."
            ):  # some hidden file (probably created by OS, especially the macOS)
                continue

            source_file_rel_path = str(child.relative_to(build_dir).parent)
            contract_name = child.name.split(".dbg.json")[0]

            with open(child, "r") as f:
                try:
                    dbg_info = json.load(f)
                except Exception:
                    continue
                # buildInfo is relative to the artifacts directory (with symlinks, like ../),
                # so we need to join the path with the build_dir and resolve it
                result[source_file_rel_path][contract_name] = child.parent.joinpath(
                    Path(dbg_info["buildInfo"])
                ).resolve()

        return result

    @property
    @lru_cache(maxsize=1)
    def build_info(self) -> Dict[str, Dict[str, Path]]:
        return self._get_build_info(self.build_dir)

    def get_source(self, source_path: str, sources: Dict[str, Dict[str, str]]) -> str:
        if (
            self.map_to_original_source
            and Path(self.normalize_path(source_path) + ".original").is_file()
        ):
            return get_content_from_file(self.normalize_path(source_path) + ".original")
        return sources[source_path]["content"]

    @lru_cache(maxsize=1)
    def process_artifacts(self) -> Tuple[Dict[str, List[Contract]], Dict[str, Source]]:
        result_contracts = defaultdict(list)
        result_sources = {}

        _seen_source_files = defaultdict(set)
        # here we reverse the build_info to have a mapping from build_info_path to source_file (along with contracts)
        build_info_paths: Dict[Path, Dict[str, List[str]]] = defaultdict(
            partial(defaultdict, list)
        )
        for source_file_name, contracts in self.build_info.items():
            for contract_name, build_info_path in contracts.items():
                _seen_source_files[source_file_name].add(build_info_path)
                build_info_paths[build_info_path][source_file_name].append(
                    contract_name
                )

        _sources_in_multiple_build_info = {}
        for source_file_name, _build_info_paths in _seen_source_files.items():
            if len(_build_info_paths) > 1:
                _sources_in_multiple_build_info[source_file_name] = _build_info_paths

        if _sources_in_multiple_build_info:
            # This is a special (maybe never occurring) case where the same source file is present in multiple
            # build_info files. If this happens, we want to catch that and try to handle it gracefully (for
            # proper handling), so for now we need to add them to the function's context to submit to the analytics
            # server for further investigation.
            # NOTE: this info will be sent to the analytics server only if the user has opted in
            Session.set_context(
                sources_in_multiple_build_info=_sources_in_multiple_build_info
            )

        project_sources = list(_seen_source_files.keys())

        # each build_info file has a list of source files and their contracts
        # we need to process each build_info_path separately, as each build_info file has its own source_ids
        # and ast nodes
        for build_info_path, source_files in build_info_paths.items():
            # TODO: handle case when different build_info_path has different source_ids for the same source file
            with open(build_info_path, "r") as f:
                build_info = json.load(f)

            source_ids: List[int] = []
            source_paths = {}

            for source_name, source in build_info["output"]["sources"].items():
                source_ids.append(source["id"])
                source_paths[str(source["id"])] = source_name

                source_name_path = str(Path(source_name))

                if (
                    source_name_path not in project_sources
                    and source_name not in result_sources
                ):
                    # If the source_name isn't in project sources, it's some dependency outside the contracts dir.
                    # Add one to result sources if it wasn't already.
                    result_sources[source_name] = {
                        "fileIndex": source["id"],
                        "source": self.get_source(
                            source_name, build_info["input"]["sources"]
                        ),
                        "ast": source["ast"],
                    }

                if (
                    source_name_path in project_sources
                    and source_name_path in source_files
                ):
                    # we need to store the source file content and ast node for each source file
                    # belonging to the current build_info file. Same source file can be present in multiple
                    # build_info files, so we need to store the source file content and ast only from
                    # the appropriate build_info file.
                    result_sources[source_name] = {
                        "fileIndex": source["id"],
                        "source": self.get_source(
                            source_name, build_info["input"]["sources"]
                        ),
                        "ast": source["ast"],
                    }

            for source_file, contracts in source_files.items():
                source_file_posix = self.as_posix(source_file)
                for contract_name in contracts:
                    # solidity build info files use posix paths, and if we are on Windows, we need to
                    # normalize paths to posix style.
                    contract = build_info["output"]["contracts"][source_file_posix][
                        contract_name
                    ]

                    unlinked_libs = self.detect_unlinked_libs(contract)

                    try:
                        contract_obj = {
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
                            "mainSourceFile": source_file_posix,
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
                        result_contracts[source_file_posix].append(contract_obj)
                        if unlinked_libs:
                            self._unlinked_libraries.append(
                                (contract_obj, unlinked_libs)
                            )
                    except KeyError as e:
                        raise BuildArtifactsError(
                            f"Build artifact did not contain expected key. Contract: {contract}: \n{e}"
                        )

        return result_contracts, result_sources

    def unlinked_libraries(self) -> List[Tuple[Contract, Dict[str, Set[str]]]]:
        return self._unlinked_libraries
