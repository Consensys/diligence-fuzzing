from pathlib import Path
from typing import Dict


def db_calls_mock(_contracts: Dict[str, Dict[str, any]], base_path: str):
    contracts = []

    contracts_paths = [
        {"source": {"sourcePath": str(Path(base_path).joinpath(v["contractPath"]))}}
        for v in _contracts.values()
    ]

    for contract_name, data in _contracts.items():
        contracts.append(
            {
                "name": contract_name,
                "compilation": {"processedSources": contracts_paths},
            }
        )

    def mock(query: str, *args, **kwargs):
        if "projectId(input:" in query:
            return {
                "projectId": "0x2d27ac8b776bcc7d5e2b4d3d9e38522cd44ab2309458356d8ddfadb5684d5304"
            }

        return {"project": {"contracts": contracts}}

    return mock
