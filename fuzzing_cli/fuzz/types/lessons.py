from typing import List, Optional

from typing_extensions import TypedDict

from .rpc import SeedSequenceTransaction


class RunningLesson(TypedDict):
    description: str
    numberOfBlocks: int
    lastBlockHash: Optional[str]


class Lesson(TypedDict):
    description: str
    transactions: List[List[SeedSequenceTransaction]]
    lastBlockHash: Optional[str]


class FuzzingLessons(TypedDict):
    runningLesson: Optional[RunningLesson]
    lessons: List[Lesson]
