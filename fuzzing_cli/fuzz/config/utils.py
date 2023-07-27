from pathlib import Path
from typing import Dict, Optional

from ruamel.yaml import YAML

yaml = YAML()
yaml.indent(offset=2, sequence=4)


def merge(
    config: Dict[str, any], update: Dict[str, any], _key: Optional[str] = None
) -> Dict[str, any]:
    for key, value in update.items():
        if type(value) == dict:
            config[key] = merge(config.get(key, {}), value)
            continue
        config[key] = value
    return config


def update_config(config_path: Path, update: Dict[str, any]):
    with config_path.open("r") as f:
        config = yaml.load(f)
        config = merge(config, update)

    with config_path.open("w") as f:
        yaml.dump(config, f)


def parse_config(config_path: Path) -> Dict[str, any]:
    with config_path.open("r") as f:
        config = yaml.load(f)
    return config


def omit_none(d: Dict[str, any]) -> Dict[str, any]:
    return {k: v for k, v in d.items() if v is not None}
