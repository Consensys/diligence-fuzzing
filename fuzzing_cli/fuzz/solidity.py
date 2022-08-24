"""This module contains functions to generate Solidity-related payloads."""

import logging
import re
from functools import cmp_to_key
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import click
import semantic_version
import solcx
import solcx.exceptions

from ..util import get_content_from_file

LOGGER = logging.getLogger("fuzzing-cli")
PRAGMA_PATTERN = r"pragma solidity [\^<>=]*(\d+\.\d+\.\d+);"
RGLOB_BLACKLIST = ["node_modules"]


class SolidityJob:
    def __init__(self, targets: List[Path]):
        super().__init__()
        self.targets = targets
        self.payloads = []

    def solc_version_from_source(self, source: str, default_version: str) -> str:
        solc_version = re.findall(PRAGMA_PATTERN, source)
        if not (solc_version or default_version):
            # no pragma found, user needs to specify the version
            raise click.exceptions.UsageError(
                "No pragma found - please specify a solc version with --solc-version"
            )

        return f"v{default_version or solc_version[0]}"

    @staticmethod
    def setup_solcx(solc_version: str):
        if solc_version not in solcx.get_installed_solc_versions():
            try:
                LOGGER.debug(f"Installing solc {solc_version}")
                solcx.install_solc(solc_version)
            except Exception as e:
                raise click.exceptions.UsageError(
                    f"Error installing solc version {solc_version}: {e}"
                )
        solcx.set_solc_version(solc_version, silent=True)

    def solcx_compile(
        self, path: str, remappings: Tuple[str], solc_path: str = None
    ) -> Dict:
        result = solcx.compile_standard(
            solc_binary=solc_path,
            input_data={
                "language": "Solidity",
                "sources": {
                    str(target): {"urls": [str(target)]} for target in self.targets
                },
                "settings": {
                    "remappings": [r.format(pwd=path) for r in remappings]
                    or [
                        f"openzeppelin-solidity/={path}/node_modules/openzeppelin-solidity/",
                        f"openzeppelin-zos/={path}/node_modules/openzeppelin-zos/",
                        f"zos-lib/={path}/node_modules/zos-lib/",
                    ],
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object",
                                "evm.bytecode.sourceMap",
                                "evm.deployedBytecode.object",
                                "evm.deployedBytecode.sourceMap",
                            ],
                            "": ["ast"],
                        }
                    },
                    "optimizer": {"enabled": True, "runs": 200},
                },
            },
            allow_paths=[path],
        )
        base_path = Path()
        for source_name, data in result.get("sources", {}).items():
            data["source"] = get_content_from_file(
                str(base_path.cwd().joinpath(source_name))
            )

        for contract_path, data in result.get("contracts", {}).items():
            for contract, contract_data in data.items():
                contract_data["evm"]["bytecode"]["object"] = self.patch_solc_bytecode(
                    contract_data["evm"]["bytecode"]["object"]
                )

        return result

    def compile(
        self,
        version: Optional[str],
        solc_path: Optional[str] = None,
        remappings: Tuple[str] = None,
    ):
        """
        This function will open the file, try to detect the used solc version from
        the pragma definition, and automatically compile it. If the given solc
        version is not installed on the client's system, it will be automatically
        downloaded.

        :param version: The solc version to use for compilation
        :param solc_path: The path to a custom solc executable
        :param remappings: Import remappings to pass to solcx
        """
        if version:
            self.setup_solcx(version)
        elif solc_path is None:
            solc_versions_in_use: Set[str] = set()
            for t in self.targets:
                with open(t, "r") as f:
                    source = f.read()
                    solc_versions_in_use.add(
                        self.solc_version_from_source(
                            source=source, default_version=version
                        )
                    )
            if len(solc_versions_in_use) > 1:
                LOGGER.debug(
                    f"Found multiple versions of solidity: {', '.join(list(solc_versions_in_use))}."
                    f" Selecting the most recent one"
                )
                solc_version = (
                    "v"
                    + sorted(
                        [v[1:] for v in solc_versions_in_use],
                        key=cmp_to_key(semantic_version.compare),
                    )[-1]
                )
            else:
                solc_version = solc_versions_in_use.pop()

            self.setup_solcx(solc_version)

        try:
            cwd = str(Path.cwd().absolute())
            LOGGER.debug(f"Compiling {self.targets} under allowed path {cwd}")
        except solcx.exceptions.SolcError as e:
            raise click.exceptions.UsageError(f"Error compiling source with solc: {e}")

        return self.solcx_compile(path=cwd, remappings=remappings, solc_path=solc_path)

    @staticmethod
    def patch_solc_bytecode(code: str) -> str:
        """Patch solc bytecode placeholders.

        This function patches placeholders in solc output. These placeholders are meant
        to be replaced with deployed library/dependency addresses on deployment, but do not form
        valid EVM bytecode. To produce a valid payload, placeholders are replaced with the zero-address.

        :param code: The bytecode to patch
        :return: The patched bytecode with the zero-address filled in
        """
        return re.sub(re.compile(r"__\$.{34}\$__"), "0" * 40, code)
