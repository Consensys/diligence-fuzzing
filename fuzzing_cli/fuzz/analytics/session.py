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

import click
import requests
from appdirs import user_data_dir
from click import ClickException
from elasticapm.conf import Config, VersionedConfig
from elasticapm.utils import stacks, varmap
from elasticapm.utils.encoding import shorten

from fuzzing_cli import __version__
from fuzzing_cli.fuzz.config import FuzzingOptions
from fuzzing_cli.fuzz.exceptions import EmptyArtifactsError, FaaSError
from fuzzing_cli.fuzz.storage import LocalStorage


class Session:
    session_path = Path(user_data_dir("fuzzing-cli", "ConsenSys") + "/session.json")
    storage = threading.local()

    @classmethod
    def set_session_path(cls, _session_path: Path):
        cls.session_path = _session_path

    @classmethod
    def start_function(cls, function_name):
        cls.storage.function = function_name
        cls.storage.context = {}

    @classmethod
    def end_function(cls, result: str):
        call = {
            "functionName": cls.storage.function,
            "result": result,
            **cls.storage.context,
        }
        session = cls.get_session()
        function_calls = session.get("functionCalls", [])
        function_calls.append(call)
        session["functionCalls"] = function_calls
        cls._save_session(session)
        delattr(cls.storage, "function")
        delattr(cls.storage, "context")

    @classmethod
    def capture_exception(cls):
        exc_type, exc_value, exc_trace = sys.exc_info()
        function_name = cls.storage.function
        call = {
            "functionName": function_name,
            "result": "exception",
            "errorType": str(exc_type.__name__),
            "errorMessage": str(exc_value),
            "stackTrace": traceback.format_exc(),
            **cls.storage.context,
        }
        session = cls.get_session()
        function_calls = session.get("functionCalls", [])
        function_calls.append(call)
        session["functionCalls"] = function_calls
        cls._save_session(session)
        delattr(cls.storage, "function")
        delattr(cls.storage, "context")

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
        if not os.path.exists(cls.session_path):
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

    @staticmethod
    def give_consent():
        LocalStorage.get_instance().set("consent_given", True)

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
    def upload_session(cls, end_function: bool = False):
        if end_function:
            cls.end_function("success")
        options = FuzzingOptions(no_exc=True)
        session = cls.get_session()
        if not cls._consent_given():
            cls.end_session()
            return
        try:
            requests.post(
                f"{options.analytics_endpoint}/sessions",
                json=session,
                headers={"Content-Type": "application/json"},
            )
        except:
            pass
        cls.end_session()

    @classmethod
    def report_crash(cls):
        frames = stacks.get_stack_info(
            stacks.iter_stack_frames(skip=1, config=VersionedConfig(Config(), None)),
            with_locals=True,
            library_frame_context_lines=5,
            in_app_frame_context_lines=5,
            locals_processor_func=lambda local_var: varmap(
                lambda k, v: shorten(
                    v, list_length=10, string_length=200, dict_length=10
                ),
                local_var,
            ),
        )
        exc_type, exc_value, exc_trace = sys.exc_info()
        crash_report = {
            "errorType": str(exc_type.__name__),
            "errorMessage": str(exc_value),
            "stackTrace": traceback.format_exc(),
            "stackFrames": [
                # remove context_metadata to avoid json serialization errors
                {k: v for k, v in frame.items() if k != "context_metadata"}
                for frame in frames[:6]
            ],
            **(cls.storage.context if hasattr(cls.storage, "context") else {}),
        }

        options = FuzzingOptions(no_exc=True)
        try:
            requests.post(
                f"{options.analytics_endpoint}/crash-reports",
                json=crash_report,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            pass
        cls.end_session()


def trace(name: str, upload_session: bool = False):
    def trace_factory(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                Session.start_function(name)
                func(*args, **kwargs)
                Session.end_function("success")
            except Exception as e:
                expected_exceptions = [
                    FaaSError,
                    EmptyArtifactsError,
                    ClickException,
                ]
                if not any(isinstance(e, exc) for exc in expected_exceptions):
                    exc_type, exc_value, exc_trace = sys.exc_info()
                    report_crash: bool = click.confirm(
                        f"An unexpected error occurred: {str(exc_type.__name__)}: {str(exc_value)}\n"
                        f"Do you want to report this error?",
                        default=True,
                    )
                    if report_crash:
                        Session.report_crash()
                        Session.capture_exception()
                        return

                Session.capture_exception()
                raise
            finally:
                if upload_session:
                    Session.upload_session()

        return wrapper

    return trace_factory
