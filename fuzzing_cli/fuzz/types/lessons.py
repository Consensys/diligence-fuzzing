from typing import List, Optional

from typing_extensions import TypedDict

from .rpc import SeedSequenceTransaction


class RunningLesson(TypedDict):
    description: str
    numberOfBlocks: int


class Lesson(TypedDict):
    description: str
    transactions: List[List[SeedSequenceTransaction]]


class FuzzingLessons(TypedDict):
    runningLesson: Optional[RunningLesson]
    lessons: List[Lesson]
