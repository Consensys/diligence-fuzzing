from .brownie import BrownieArtifacts
from .dapptools import DapptoolsArtifacts
from .foundry import FoundryArtifacts
from .generic import IDEArtifacts
from .hardhat import HardhatArtifacts
from .repository import IDERepository
from .truffle import TruffleArtifacts

# Initializing of IDERepository singleton
# NOTE: Each new IDE should register respective class here
repo = IDERepository()

repo.register_ide(TruffleArtifacts)
repo.register_ide(HardhatArtifacts)
repo.register_ide(BrownieArtifacts)
repo.register_ide(DapptoolsArtifacts)
repo.register_ide(FoundryArtifacts)

IDERepository.set_instance(repo)
