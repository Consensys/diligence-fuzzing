import logging
from typing import Type

from click import UsageError

from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.ide import IDEArtifacts, IDERepository

LOGGER = logging.getLogger("fuzzing-cli")


def detect_ide(options: FuzzingOptions) -> Type[IDEArtifacts]:
    repo = IDERepository.get_instance()
    if options.ide:
        LOGGER.debug(f'"{options.ide}" IDE is specified')
        _IDEClass = repo.get_ide(options.ide)
    else:
        LOGGER.debug("IDE not specified. Detecting one")
        _IDEClass = repo.detect_ide()
        if not _IDEClass:
            LOGGER.debug("No supported IDE was detected")
            raise UsageError(f"No supported IDE was detected")
        LOGGER.debug(f'"{_IDEClass.get_name()}" IDE detected')
    return _IDEClass
