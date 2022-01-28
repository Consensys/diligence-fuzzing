from typing import Dict, Type

from .generic import IDE, IDEArtifacts, IDEJob


class ArtifactsNotRegistered(Exception):
    def __init__(self, ide):
        super(ArtifactsNotRegistered, self).__init__(
            f"Artifacts for {ide.name} not registered"
        )


class JobNotRegistered(Exception):
    def __init__(self, ide):
        super(JobNotRegistered, self).__init__(f"Job for {ide.name} not registered")


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
        artifact_class = self.artifacts_classes[ide]
        if not artifact_class:
            raise ArtifactsNotRegistered(ide)
        return artifact_class

    def register_job(self, ide: IDE, _class: Type[IDEJob]):
        self.ide_jobs[ide] = _class

    def get_job(self, ide: IDE) -> Type[IDEJob]:
        job = self.ide_jobs[ide]
        if not job:
            raise JobNotRegistered(ide)
        return job
