import logging
from collections import defaultdict
from os.path import commonpath
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import click

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.ide import IDEArtifacts
from fuzzing_cli.fuzz.lessons import FuzzingLessons
from fuzzing_cli.fuzz.rpc.rpc import CONTRACT_ADDRESS, RPCClient
from fuzzing_cli.fuzz.types import Contract, SeedSequenceTransaction

LOGGER = logging.getLogger("fuzzing-cli")


class NoTransactionFound(Exception):
    pass


def _uniq(lst: List[str]) -> List[str]:
    """
    Remove duplicates from a list while preserving order
    """
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]


class CorpusRepository:
    def __init__(
        self,
        rpc: RPCClient,
        artifacts: IDEArtifacts,
        options: FuzzingOptions,
        corpus_target: Optional[str],
    ):
        self._corpus_target = corpus_target
        self._rpc = rpc
        self._artifacts = artifacts
        self._options = options
        (
            self._address_to_contract_mapping,
            self._contract_to_address_mapping,
            self._source_file_to_address_mapping,
        ) = self._construct_address_contract_mapping()
        self._initialize()

    def _initialize(
        self,
        addresses_under_test: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
    ) -> None:
        (
            self.contract_targets,
            self.source_targets,
        ) = self._construct_targets(addresses_under_test, targets)

        self.validation_errors = []
        self._validate()

    def apply_auto_fix(self, suggested_fixes: List[Dict[str, Any]]) -> None:
        """
        Apply the suggested fixes to the config file. Suggested fixes are of the following types:
            - Add a new address target
            - Add a new source target
            - Remove an address target
            - Remove a source target
        """
        addresses_under_test = self.contract_targets[:]  # make shallow copy of the list
        targets = self.source_targets[:]  # make shallow copy of the list
        for fix in suggested_fixes:
            if fix["type"] == "add_addresses":
                addresses_under_test.extend(fix["data"])
                continue
            if fix["type"] == "add_targets":
                targets.extend(fix["data"])
                continue
            if fix["type"] == "remove_addresses":
                addresses_under_test = [
                    address
                    for address in addresses_under_test
                    if address not in fix["data"]
                ]
                continue
            if fix["type"] == "remove_targets":
                targets = [target for target in targets if target not in fix["data"]]
                continue
        # Re-initialize the repository with the new targets and addresses, and validate
        self._initialize(addresses_under_test, targets)

    @property
    def _fuzzing_lessons(self) -> Tuple[Set[str], List[List[SeedSequenceTransaction]]]:
        """Get the fuzzing lessons to be added to the campaign's seed state"""
        blocks_to_skip: Set[str] = set([])
        suggested_seed_seqs: List[List[SeedSequenceTransaction]] = []
        for lesson in FuzzingLessons.get_lessons():
            click.secho(
                f"Lesson \"{lesson['description']}\" will be added to the campaign's seed state"
            )
            LOGGER.debug(
                f"Adding lesson \"{lesson['description']}\" to the campaign's seed state"
            )
            blocks_to_skip.update(
                {b["blockNumber"] for s in lesson["transactions"] for b in s}
            )
            suggested_seed_seqs.extend(lesson["transactions"])
        return blocks_to_skip, suggested_seed_seqs

    def _get_contract_by_address(
        self,
        contract_address: CONTRACT_ADDRESS,
    ) -> Optional[Contract]:
        """Get the artifacts of the contracts at the given addresses"""
        deployed_bytecode = self._rpc.get_code(contract_address)
        if deployed_bytecode is None:  # it's unknown contract
            LOGGER.warning(
                f'No deployed bytecode is found in an RPC node for contract: "{contract_address}"'
            )
            return None
        contract = self._artifacts.get_contract(deployed_bytecode)
        if not contract or contract.get("mainSourceFile", None) is None:
            LOGGER.warning(
                f'Contract "{contract_address}" could not be found in sources.'
                f" You can try to manually set the sources using the targets option. "
                f"More at: https://fuzzing-docs.diligence.tools/getting-started/configuring-the-cli#configuration"
            )
            return None
        return contract

    @property
    def all_deployed_contracts_addresses(self) -> List[str]:
        """Get all the deployed contracts addresses from an RPC node excluding transactions from the fuzzing lessons"""
        blocks_to_skip, _ = self._fuzzing_lessons
        contracts_addresses = self._rpc.get_all_deployed_contracts_addresses(
            blocks_to_skip
        )
        return contracts_addresses

    @staticmethod
    def _contract_key(contract: Contract):
        return contract["mainSourceFile"], contract["contractName"]

    def _construct_address_contract_mapping(
        self,
    ) -> Tuple[Dict[str, Contract], Dict[Tuple[str, str], str], Dict[str, List[str]]]:
        address_to_contract_mapping = {}
        contract_to_address_mapping = {}
        # source file to contract addresses mapping. One source file can have multiple contracts, so we need to
        # keep track of all the contracts addresses for a given source file
        source_file_to_address_mapping = defaultdict(list)
        for contract_address in self.all_deployed_contracts_addresses:
            contract = self._get_contract_by_address(contract_address)
            if contract is None:
                address_to_contract_mapping[contract_address] = None
                continue
            address_to_contract_mapping[contract_address] = contract
            contract_to_address_mapping[self._contract_key(contract)] = contract_address
            source_file_to_address_mapping[contract["mainSourceFile"]].append(
                contract_address
            )

        return (
            address_to_contract_mapping,
            contract_to_address_mapping,
            source_file_to_address_mapping,
        )

    @staticmethod
    def _path_inclusion_checker(paths: List[str]):
        """Construct a function that checks if a given path is in the list of paths.
        The paths can be files or folders"""
        directory_paths: List[str] = []
        file_paths: List[str] = []
        for _path in paths:
            if Path(_path).is_dir():
                directory_paths.append(_path)
            else:
                file_paths.append(_path)

        def inner_checker(path: str):
            if path in file_paths:
                # we have found exact file match
                return True
            # try to find folder match
            for dir_path in directory_paths:
                if commonpath([dir_path, path]) == dir_path:
                    # file is in the directory
                    return True
            return False

        return inner_checker

    def _construct_targets(
        self,
        addresses_under_test: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
    ) -> Tuple[List[CONTRACT_ADDRESS], List[str]]:
        """
        Construct the targets from the addresses under test and the targets options
        or from provided addresses under test and targets (after prompting for automatic fixes).
        """
        if addresses_under_test is None:
            addresses_under_test = self._options.addresses_under_test
        if targets is None:
            targets = self._options.targets[
                :
            ]  # make a copy of the targets to not modify the original list

        return _uniq(addresses_under_test), _uniq(targets)

    @property
    def seed_state(self) -> Dict[str, any]:
        try:
            blocks_to_skip, suggested_seed_seqs = self._fuzzing_lessons
            processed_transactions = self._rpc.get_transactions(
                block_numbers_to_skip=list(blocks_to_skip)
            )

            if len(processed_transactions) == 0:
                raise NoTransactionFound(
                    "No transactions were found in an Ethereum RPC node"
                )

            setup = {
                "address-under-test": list(self.contract_targets)[0],
                "steps": processed_transactions,
                # make None if there are no other addresses under test to avoid sending empty list
                "other-addresses-under-test": list(self.contract_targets)[1:] or None,
            }

            """Get a seed state for the target contract to be used by Harvey"""
            if self._corpus_target:
                setup["target"] = self._corpus_target
            if len(suggested_seed_seqs) > 0:
                setup["suggested-seed-seqs"] = suggested_seed_seqs
            return {
                "discovery-probability-threshold": 0.0,
                "assertion-checking-mode": 1,
                "num-cores": self._options.number_of_cores,
                "analysis-setup": setup,
            }
        except NoTransactionFound:
            raise
        except Exception as e:
            raise Exception(
                "Unable to generate the seed state. Please check configuration and try again."
            ) from e

    def _validate(self):
        """
        Here we perform the following checks:
        1. All contracts deployed at the addresses specified in the addresses_under_test are found on the RPC.
        2. All contract deployed on the RPC are found in artifacts of the project.
        3. All contracts deployed on the RPC are provided as targets and as addresses under test.
        4. All contracts provided as addresses under test have a corresponding target (source file name)
           provided as well.
        5. All contracts provided as targets (source file name) have a corresponding deployed contract's
           provided as an address under test.
        6. All contracts provided as targets (source file name) has been deployed on the RPC.
        """
        unknown_contracts = []
        contracts_with_no_artifact = []
        # contract address was set as address under test, but its source file was not provided as a target
        source_target_not_set = []
        contract_target_not_set = []
        not_deployed_contracts = []

        processed_source_targets = [
            self._artifacts.normalize_path(s) for s in self.source_targets
        ]
        path_check = self._path_inclusion_checker(processed_source_targets)

        for contract_address in self.contract_targets:
            # 1. All contracts deployed at the addresses specified in the addresses_under_test are found on the RPC.
            if contract_address not in self.all_deployed_contracts_addresses:
                unknown_contracts.append(contract_address)
                continue

            contract = self._address_to_contract_mapping.get(contract_address, None)
            # 2. All contract deployed on the RPC are found in artifacts of the project.
            if contract is None:
                LOGGER.debug(
                    f'No artifact found for contract with address: "{contract_address}"'
                )
                contracts_with_no_artifact.append(contract_address)
                continue
            # 4. All contracts provided as addresses under test have a corresponding target provided as well.
            if not path_check(
                self._artifacts.normalize_path(contract["mainSourceFile"])
            ):
                # This is a contract that's been provided as address under test,
                # but its source file was not provided as a target
                source_target_not_set.append(
                    (
                        contract_address,
                        self._artifacts.normalize_path(contract["mainSourceFile"]),
                    )
                )

        for source_file_name in self.source_targets:
            # here we use path_check because target could be a directory,
            # so we need to check if the source file is in the directory
            # if the target is a file, then path_check will just check if the source file is the same as the target
            source_file_name = self._artifacts.normalize_path(source_file_name)
            _path_check = self._path_inclusion_checker([source_file_name])
            for contract in self._artifacts.contracts:
                if not _path_check(
                    self._artifacts.normalize_path(contract["mainSourceFile"])
                ):
                    continue
                contract_address = self._contract_to_address_mapping.get(
                    self._contract_key(contract), None
                )
                # 6. All contracts provided as targets (source file name) has been deployed on the RPC.
                if contract_address is None:
                    not_deployed_contracts.append(self._contract_key(contract))
                    continue
                # 5. All contracts provided as targets (source file name) have a corresponding
                # deployed contract's address provided as an address under test.
                if contract_address not in self.contract_targets:
                    contract_name = self._address_to_contract_mapping[contract_address][
                        "contractName"
                    ]
                    contract_target_not_set.append(
                        (contract_address, source_file_name, contract_name)
                    )
                    continue

        # 3. All contracts deployed on the RPC are provided as targets and as addresses under test.
        not_targeted_contracts = []
        targets_in_use = {
            *self.contract_targets,
            *[addr for addr, _, _ in contract_target_not_set],
            *[addr for addr, _ in source_target_not_set],
            *contracts_with_no_artifact,
        }
        for contract_address in self.all_deployed_contracts_addresses:
            if contract_address in targets_in_use:
                continue
            contract = self._get_contract_by_address(contract_address)
            if contract is None:
                # This is the contract without the artifact which should be caught by the previous checks,
                # so we skip it here
                continue
            not_targeted_contracts.append(
                (
                    contract_address,
                    contract.get("mainSourceFile"),
                    contract.get("contractName"),
                )
            )

        if unknown_contracts:
            self.validation_errors.append(
                {
                    "type": "unknown_contracts",
                    "data": unknown_contracts,
                }
            )

        if contracts_with_no_artifact:
            self.validation_errors.append(
                {
                    "type": "contracts_with_no_artifact",
                    "data": contracts_with_no_artifact,
                }
            )

        if contract_target_not_set:
            self.validation_errors.append(
                {
                    "type": "contract_target_not_set",
                    "data": contract_target_not_set,
                }
            )

        if source_target_not_set:
            self.validation_errors.append(
                {
                    "type": "source_target_not_set",
                    "data": source_target_not_set,
                }
            )

        if not_deployed_contracts:
            self.validation_errors.append(
                {
                    "type": "not_deployed_contracts",
                    "data": not_deployed_contracts,
                }
            )

        if not_targeted_contracts:
            self.validation_errors.append(
                {
                    "type": "not_targeted_contracts",
                    "data": not_targeted_contracts,
                }
            )
