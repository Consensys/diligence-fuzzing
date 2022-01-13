from typing import Dict, Type

from .generic import IDE, IDEArtifacts, IDEJob


class IDERepository:
    instance: "IDERepository"

    def __init__(self):
        self.artifacts_classes: Dict[IDE, Type[IDEArtifacts]] = {}
        self.ide_jobs: Dict[IDE, Type[any]] = {}

    @classmethod
    def set_instance(cls, _instance: "IDERepository"):
        cls.instance = _instance

    @classmethod
    def get_instance(cls) -> "IDERepository":
        return cls.instance

    def register_artifacts(self, ide: IDE, _class: Type[IDEArtifacts]):
        self.artifacts_classes[ide] = _class

    def get_artifacts(self, ide: IDE) -> Type[IDEArtifacts]:
        return self.artifacts_classes[ide]

    def register_job(self, ide: IDE, _class: Type[IDEJob]):
        self.ide_jobs[ide] = _class

    def get_job(self, ide: IDE) -> Type[IDEJob]:
        return self.ide_jobs[ide]
