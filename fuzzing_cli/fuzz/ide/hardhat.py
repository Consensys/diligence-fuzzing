import os
from pathlib import Path
from typing import Dict, List

from fuzzing_cli.fuzz.ide.generic import Contract, Source

from .foundry import FoundryArtifacts


class HardhatArtifacts(FoundryArtifacts):
    add_compilation_hint = False

    @classmethod
    def get_name(cls) -> str:
        return "hardhat"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "hardhat.config.ts" in files or "hardhat.config.js" in files

    @staticmethod
    def get_default_build_dir() -> Path:
        return Path.cwd().joinpath("artifacts")

    @staticmethod
    def get_default_sources_dir() -> Path:
        return Path.cwd().joinpath("contracts")
