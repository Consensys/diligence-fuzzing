import json
import os
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional

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

    @contextmanager
    def config(self) -> Generator[Dict[str, Any], None, None]:
        # this is a context manager that allows you to read and write to the config file.
        # it will automatically save the config file when the context manager is exited
        _config = self._config
        yield _config
        self._update_config(_config)

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

    def get(self, key: str, default: Any = None) -> Optional[Any]:
        return self._config.get(key, default)

    def set(self, key: str, value: str) -> None:
        config = self._config
        config[key] = value
        self._update_config(config)
