from .brownie import BrownieArtifacts, BrownieJob
from .generic import IDE, IDEArtifacts, IDEJob, IDEPayload, determine_ide
from .hardhat import HardhatArtifacts, HardhatJob
from .repository import IDERepository
from .truffle import TruffleArtifacts, TruffleJob

# Initializing of IDERepository singleton
# NOTE: Each new IDE should register *_Artifacts and *_Job classes here
repo = IDERepository()

repo.register_artifacts(IDE.TRUFFLE, TruffleArtifacts)
repo.register_artifacts(IDE.HARDHAT, HardhatArtifacts)
repo.register_artifacts(IDE.BROWNIE, BrownieArtifacts)

repo.register_job(IDE.TRUFFLE, TruffleJob)
repo.register_job(IDE.HARDHAT, HardhatJob)
repo.register_job(IDE.BROWNIE, BrownieJob)

IDERepository.set_instance(repo)
