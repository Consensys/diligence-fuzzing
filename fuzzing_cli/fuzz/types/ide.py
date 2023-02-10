from typing import Dict, List, Optional

from typing_extensions import TypedDict


class IDEPayload(TypedDict):
    contracts: List[any]
    sources: Dict[str, any]


class Contract(TypedDict):
    sourcePaths: Dict[str, str]
    deployedSourceMap: str
    deployedBytecode: str
    sourceMap: str
    bytecode: str
    contractName: str
    mainSourceFile: str
    ignoredSources: Optional[List[int]]


class Source(TypedDict):
    fileIndex: int
    source: str
    ast: Dict[str, any]
