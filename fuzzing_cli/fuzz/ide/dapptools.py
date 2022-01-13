import json
import logging
from pathlib import Path
from typing import List, Dict

from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.ide.generic import IDEArtifacts, JobBuilder

from ...util import get_content_from_file, sol_files_by_directory

LOGGER = logging.getLogger("fuzzing-cli")


class DapptoolsArtifacts(IDEArtifacts):
    def __init__(self, build_dir=None, targets=None, map_to_original_source=False):
        # self._include is an array with all the solidity file paths under the targets
        self._include = []
        if targets:
            include = []
            for target in targets:
                include.extend(sol_files_by_directory(target))
            self._include = include

        self._build_dir = build_dir or Path("./out")

        # self._get_build_artifacts goes through each .json build file and extracts the Source file it references
        # A source file may contain several contracts, so it is possible that a given source file
        # will be pointed to by multiple build artifacts
        # build_files_by_source_file is a dictionary where the key is a source file name
        # and the value is an array of build artifacts (contracts)
        build_files_by_source_file, source_files = self._get_build_artifacts(self._build_dir)
        # print(build_files_by_source_file)



        # we then extract the contracts and sources from the build artifacts
        self._contracts, self._sources = self.fetch_data(
            build_files_by_source_file, source_files, map_to_original_source
        )

    @property
    def contracts(self):
        return self._contracts

    @property
    def sources(self):
        return self._sources

    @staticmethod
    def _get_build_artifacts(build_dir) -> tuple:
        build_files_by_source_file = {}
        source_files = {}

        build_dir = Path(build_dir)

        if not build_dir.is_dir():
            raise BuildArtifactsError("Build directory doesn't exist")

        for child in build_dir.glob("**/*"):
            if not child.is_file():
                continue
            if not child.name.endswith(".json"):
                continue

            data = json.loads(child.read_text("utf-8"))
            build_files_by_source_file.update(data["contracts"])
            source_files.update(data["sources"])

        return build_files_by_source_file, source_files

    def fetch_data(self, build_files_by_source_file, source_files, map_to_original_source=False):
        ''' example build_files_by_source_file
            {
                'contracts': {
                    'src/Token.sol':{
                        'Ownable':{
                            abi:[...],
                            evm: {
                                bytecode: {...},
                                deployedBytecode: {...},
                            }
                        },
                        'OtherContractName'
                    }
                },
                'sources': {
                    'src/Token.sol':{
                        ast: '',
                        id: 0
                    }
                }
            }
        '''



        result_contracts = {}
        result_sources = {}

        # ( 'contracts/Token.sol', {'allSourcePaths':..., 'deployedSourceMap': ... } )
        for source_file, contracts in build_files_by_source_file.items():
            print("Source file: ", source_file)

            if source_file not in self._include:
                continue
            result_contracts[source_file] = []
            for (contract_name, contract) in contracts.items():
                # We get the build items from dapptools and rename them into the properties used by the FaaS
                try:
                    result_contracts[source_file] += [
                        {
                           # "sourcePaths": contract["allSourcePaths"],
                            "deployedSourceMap": contract["evm"]["deployedBytecode"]["sourceMap"],
                            "deployedBytecode": contract["evm"]["deployedBytecode"]["object"],
                            "sourceMap": contract["evm"]["bytecode"]["sourceMap"],
                            "bytecode": contract["evm"]["bytecode"]["object"],
                            "contractName": contract_name,
                            "mainSourceFile": source_file,
                        }
                    ]
                except KeyError as e:
                    raise BuildArtifactsError(
                        f"Build artifact did not contain expected key. Contract: {contract}: \n{e}"
                    )

        for source_file_path, source_file in source_files.items():
            file_index = source_file["id"]


            # We can select any dict on the build_files_by_source_file[source_file] array
            # because the .source and .ast values will be the same in all.
            target_file = build_files_by_source_file[source_file_path]
            result_sources[source_file_path] = {
                "fileIndex": file_index,
                "source": get_content_from_file(source_file_path),
                "ast": source_file["ast"],
            }

            if (
                map_to_original_source
                and Path(source_file_path + ".original").is_file()
            ):
                # we check if the current source file has a non instrumented version
                # if it does, we include that one as the source code
                result_sources[source_file_path][
                    "source"
                ] = get_content_from_file(source_file_path + ".original")
        print(json.dumps(result_sources))
        exit(-1)
        return result_contracts, result_sources


class DapptoolsJob:
    def __init__(
        self, target: List[str], build_dir: Path, map_to_original_source: bool
    ):
        artifacts = DapptoolsArtifacts(
            build_dir, targets=target, map_to_original_source=map_to_original_source
        )
        self._jb = JobBuilder(artifacts)
        self.payload = None

    def generate_payload(self):
        self.payload = self._jb.payload()
