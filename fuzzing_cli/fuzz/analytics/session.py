import functools
import json
import os
import platform
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

import requests
from appdirs import user_data_dir

from fuzzing_cli import __version__
from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.storage import LocalStorage


class Session:
    session_path = Path(user_data_dir("fuzzing-cli", "ConsenSys") + "/session.json")
    storage = threading.local()

    @classmethod
    def start_function(cls, function_name):
        cls.storage.function = function_name

    @classmethod
    def end_function(cls, result: str):
        call = {
            "functionName": cls.storage.function,
            "result": result,
            **(cls.storage.context if hasattr(cls.storage, "context") else {}),
        }
        session = cls.get_session()
        function_calls = session.get("function_calls", [])
        function_calls.append(call)
        cls._save_session(session)

    @classmethod
    def capture_exception(cls):
        exc_type, exc_value, exc_trace = sys.exc_info()
        function_name = cls.storage.function
        call = {
            "functionName": function_name,
            "result": "exception",
            "errorType": str(exc_type.__name__),
            "errorMessage": str(exc_value),
            "traceback": traceback.format_exc(),
            **(cls.storage.context if hasattr(cls.storage, "context") else {}),
        }

        session = cls.get_session()
        function_calls = session.get("function_calls", [])
        function_calls.append(call)
        cls._save_session(session)

    @classmethod
    def set_context(cls, **kwargs):
        cls.storage.context = kwargs

    @classmethod
    def set_local_context(
        cls,
        rpc_node_kind: Optional[str] = None,
        rpc_node_version: Optional[str] = None,
        ci_mode: Optional[bool] = None,
        user_id: Optional[str] = None,
    ):
        context = {
            "rpcNodeKind": rpc_node_kind,
            "rpcNodeVersion": rpc_node_version,
            "ciMode": ci_mode,
            "userId": user_id,
        }
        context = {k: v for k, v in context.items() if v is not None}
        if not context:
            return
        session = cls.get_session()
        session.update(context)
        cls._save_session(session)

    @classmethod
    def get_session(cls) -> Dict[str, Any]:
        if not cls.session_path.exists():
            cls.start_session()

        with cls.session_path.open() as f:
            return json.load(f)

    @classmethod
    def get_session_id(cls) -> str:
        return cls.get_session()["sessionId"]

    @classmethod
    def _save_session(cls, session):
        with cls.session_path.open("w") as f:
            json.dump(session, f)

    @staticmethod
    def _consent_given():
        return LocalStorage.get_instance().get("consent_given", False)

    @classmethod
    def start_session(cls):
        session_id = str(uuid4())

        session_dir = cls.session_path.parent
        session_dir.mkdir(parents=True, exist_ok=True)

        with cls.session_path.open("w") as f:
            json.dump(
                {
                    "sessionId": session_id,
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "pythonVersion": platform.python_version(),
                    "pythonImplementation": platform.python_implementation(),
                    "fuzzingCliVersion": __version__,
                },
                f,
            )

    @classmethod
    def end_session(cls):
        os.remove(cls.session_path)

    @classmethod
    def upload_session(cls):
        options = FuzzingOptions(no_exc=True)
        session = cls.get_session()
        if not cls._consent_given():
            return
        requests.post(
            f"{options.analytics_endpoint}/sessions",
            json=session,
            headers={"Content-Type": "application/json"},
        )
        cls.end_session()


def trace(name: str):
    def trace_factory(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                Session.start_function(name)
                func(*args, **kwargs)
                Session.end_function("success")
            except Exception:
                Session.capture_exception()
                raise

        return wrapper

    return trace_factory
