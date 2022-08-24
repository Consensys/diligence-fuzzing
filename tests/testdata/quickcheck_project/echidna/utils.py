from typing import List

from tests.common import get_test_case


def get_compilation_artifacts(targets: List[str]):
    if len(targets) > 2 or len(targets) == 0:
        raise Exception("unknown targets")
    if len(targets) == 2:
        return get_test_case(
            "testdata/quickcheck_project/echidna/combined_compilation_artifacts.json"
        )
    if "contracts/VulnerableTokenTest.sol" in targets[0]:
        return get_test_case(
            "testdata/quickcheck_project/echidna/first_contract_compilation_artifacts.json"
        )
    return get_test_case(
        "testdata/quickcheck_project/echidna/second_contract_compilation_artifacts.json"
    )


def get_processed_payload(targets):
    if len(targets) > 2 or len(targets) == 0:
        raise Exception("unknown targets")
    if len(targets) == 2:
        return get_test_case(
            "testdata/quickcheck_project/echidna/combined_processed_payload.json"
        )
    if "contracts/VulnerableTokenTest.sol" in targets[0]:
        return get_test_case(
            "testdata/quickcheck_project/echidna/first_contract_processed_payload.json"
        )
    return get_test_case(
        "testdata/quickcheck_project/echidna/second_contract_processed_payload.json"
    )
