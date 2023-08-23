import json
import os
from typing import Any, Optional

from appdirs import user_config_dir


class LocalStorage:
    instance = None

    def __init__(self, _user_config_dir: Optional[str] = None):
        self.path = _user_config_dir or user_config_dir("fuzzing-cli", "ConsenSys")

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = LocalStorage()
        return cls.instance

    @classmethod
    def set_instance(cls, instance):
        cls.instance = instance

    @property
    def _config(self):
        try:
            if not os.path.exists(self.path):
                os.makedirs(self.path)
            with open(self.path + "/config.json", "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _update_config(self, config):
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        with open(self.path + "/config.json", "w") as f:
            json.dump(config, f)

    def get(self, key: str, default: Any) -> Optional[Any]:
        return self._config.get(key, default)

    def set(self, key: str, value: str) -> None:
        config = self._config
        config[key] = value
        self._update_config(config)
