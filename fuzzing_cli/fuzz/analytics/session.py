import functools
import json
import logging
import os
import platform
import sys
import threading
import time
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
from elasticapm.utils.encoding import shorten, transform
from elasticapm.utils.stacks import get_culprit

from fuzzing_cli import __version__
from fuzzing_cli.fuzz.config import AdditionalOptions
from fuzzing_cli.fuzz.exceptions import EmptyArtifactsError, FaaSError
from fuzzing_cli.fuzz.storage import LocalStorage

LOGGER = logging.getLogger("fuzzing-cli")


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
    def end_function(cls, result: str, duration: float = None):
        call = {
            "functionName": cls.storage.function,
            "result": result,
            "duration": duration,
            "context": cls.storage.context,
        }
        session = cls.get_session()
        function_calls = session.get("functionCalls", [])
        function_calls.append(call)
        session["functionCalls"] = function_calls
        cls._save_session(session)
        delattr(cls.storage, "function")
        delattr(cls.storage, "context")

    @classmethod
    def capture_exception(cls, duration: float = None):
        exc_type, exc_value, exc_trace = sys.exc_info()
        function_name = cls.storage.function
        call = {
            "functionName": function_name,
            "result": "exception",
            "duration": duration,
            "errorType": str(exc_type.__name__),
            "errorMessage": str(exc_value),
            "stackTrace": traceback.format_exc(),
            "context": cls.storage.context,
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
        # update local context with non-None values (i.e. only updates)
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
    def consent_given():
        return LocalStorage.get_instance().get("consent_given", None)

    @staticmethod
    def give_consent(answer: bool):
        LocalStorage.get_instance().set("consent_given", answer)

    @staticmethod
    def get_device_id() -> str:
        device_id = LocalStorage.get_instance().get("device_id", None)
        if device_id is None:
            device_id = str(uuid4())
            LocalStorage.get_instance().set("device_id", device_id)
        return device_id

    @staticmethod
    def _get_device_info():
        return {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "pythonVersion": platform.python_version(),
            "pythonImplementation": platform.python_implementation(),
            "fuzzingCliVersion": __version__,
        }

    @classmethod
    def start_session(cls):
        session_dir = cls.session_path.parent
        session_dir.mkdir(parents=True, exist_ok=True)

        session = {
            "deviceId": cls.get_device_id(),
            "sessionId": str(uuid4()),
            **cls._get_device_info(),
        }

        with cls.session_path.open("w") as f:
            json.dump(session, f)

    @classmethod
    def end_session(cls):
        os.remove(cls.session_path)

    @classmethod
    def upload_session(cls, end_function: bool = False):
        LOGGER.debug("Uploading analytics session")
        if end_function:
            cls.end_function("success")
        options = AdditionalOptions()
        session = cls.get_session()
        if not cls.consent_given():
            cls.end_session()
            return
        try:
            result = requests.post(
                f"{options.analytics_endpoint}/sessions",
                json=session,
                headers={"Content-Type": "application/json"},
            )
            if result.status_code == 200:
                LOGGER.debug("Analytics session sent successfully")
            else:
                LOGGER.debug(
                    f"Failed to send analytics session. Status Code: {result.status_code}. Response: {result.text}",
                )
        except Exception as e:
            LOGGER.debug(f"Failed to send analytics session. Exception: {e}")
        cls.end_session()

    @classmethod
    def report_crash(cls):
        LOGGER.debug("Reporting crash")
        session = cls.get_session()

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
            "deviceId": cls.get_device_id(),
            **cls._get_device_info(),
            **({k: v for k, v in session.items() if k != "functionCalls"}),
            "errorType": str(exc_type.__name__),
            "errorMessage": str(exc_value),
            "errorCulprit": get_culprit(frames),
            "stackTrace": traceback.format_exc(),
            "stackFrames": [transform(frame) for frame in frames],
            "context": cls.storage.context if hasattr(cls.storage, "context") else {},
        }

        options = AdditionalOptions()
        try:
            result = requests.post(
                f"{options.analytics_endpoint}/crash-reports",
                json=crash_report,
                headers={"Content-Type": "application/json"},
            )
            if result.status_code == 200:
                LOGGER.debug("Crash report sent successfully")
            else:
                LOGGER.debug(
                    f"Failed to send crash report. Status Code: {result.status_code}. Response: {result.text}",
                )
        except Exception as e:
            LOGGER.debug(f"Failed to send crash report. Exception: {e}")
        cls.end_session()

    @classmethod
    def get_consents_status(cls):
        options = AdditionalOptions()
        report_crash = options.report_crashes
        consent_given = Session.consent_given()
        if consent_given is None:
            consent_given = options.allow_analytics
        return {
            "report_crashes": report_crash,
            "allow_analytics": consent_given,
        }


def trace(name: str, upload_session: bool = False):
    def trace_factory(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _start_time = time.perf_counter()
            try:
                Session.start_function(name)
                func(*args, **kwargs)
                Session.end_function(
                    "success", duration=time.perf_counter() - _start_time
                )
            except Exception as e:
                expected_exceptions = [
                    FaaSError,
                    EmptyArtifactsError,
                    ClickException,
                ]
                if not any(isinstance(e, exc) for exc in expected_exceptions):
                    exc_type, exc_value, exc_trace = sys.exc_info()
                    options = AdditionalOptions()
                    # if the CI mode is enabled, we need to check FUZZ_REPORT_CRASHES env variable
                    if options.ci_mode:
                        report_crash: bool = options.report_crashes
                    else:
                        if options.report_crashes:
                            # ask the user for consent in case the env variable is set to default (True)
                            report_crash: bool = click.confirm(
                                f"Oops! 🙊 Something didn't go as planned. "
                                f"Please see details below for more information: "
                                f"{str(exc_type.__name__)}: {str(exc_value)}\n"
                                f"Do you want to report this error?",
                                default=True,
                            )
                        else:
                            # if the env variable is set to False (by setting the env variable),
                            # don't ask the user for consent
                            report_crash = False
                    if report_crash:
                        Session.report_crash()
                        Session.capture_exception()
                        return

                Session.capture_exception(duration=time.perf_counter() - _start_time)

                if isinstance(e, ClickException):
                    # do not wrap the click exceptions
                    raise e
                raise ClickException(message=f"Unhandled exception - {str(e)}")

            finally:
                # TODO: better handling of saving the consent for cases when it's not confirmed interactively
                # ask for consent if not given and save the answer to the app settings
                if Session.consent_given() is None:
                    options = AdditionalOptions()
                    # if the CI mode is enabled, we need to check FUZZ_ALLOW_ANALYTICS env variable
                    if options.ci_mode:
                        consent_given = options.allow_analytics
                    else:
                        if options.allow_analytics:
                            consent_given: bool = click.confirm(
                                f"Hey there! 👋 Mind if we collect some usage analytics? "
                                f"It helps us improve and make the experience better for you and others. 🚀. "
                                f"(You can revoke the consent at any time later using "
                                f"`fuzz config set no-product-analytics`)",
                                default=True,
                            )
                        else:
                            # if the env variable is set to False (by setting the env variable),
                            # don't ask the user for consent because the user has already denied it
                            consent_given = False
                    Session.give_consent(consent_given)
                if upload_session:
                    Session.upload_session()

        return wrapper

    return trace_factory
