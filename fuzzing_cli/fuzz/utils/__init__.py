import datetime
import logging
from datetime import timezone
from typing import Any, Dict, Optional, Type

import click
import requests
from click import UsageError
from requests import Response

import fuzzing_cli
from fuzzing_cli.fuzz.config import AdditionalOptions, FuzzingOptions
from fuzzing_cli.fuzz.ide import IDEArtifacts, IDERepository
from fuzzing_cli.fuzz.storage import LocalStorage

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


def _process_version_info(response: Response, config: Dict[str, Any]) -> None:
    result = response.json()
    content_tag = response.headers.get("ETag")
    latest_version = result["info"]["version"]

    config["latest_version"] = latest_version
    config["latest_version_etag"] = content_tag
    config["latest_version_checked_at"] = datetime.datetime.now(
        timezone.utc
    ).timestamp()


def get_latest_version() -> Optional[str]:
    local_storage = LocalStorage.get_instance()
    with local_storage.config() as config:
        if (
            config.get("latest_version") is None
            or config.get("latest_version_etag") is None
        ):
            try:
                resp = requests.get("https://pypi.org/pypi/diligence-fuzzing/json")
                if resp.status_code != 200:
                    return None

                _process_version_info(resp, config)
            except Exception:
                return None
        elif (
            config.get("latest_version_checked_at") is None
            or datetime.datetime.now(timezone.utc).timestamp()
            - config["latest_version_checked_at"]
            > 86400
        ):
            try:
                resp = requests.get(
                    "https://pypi.org/pypi/diligence-fuzzing/json",
                    headers={"If-None-Match": config["latest_version_etag"]},
                )
                if resp.status_code == 304 or resp.status_code != 200:
                    # latest version has not changed or failed to get the latest version
                    # so return the cached version
                    return config["latest_version"]
                _process_version_info(resp, config)
            except Exception:
                return None

        return config["latest_version"]


def check_latest_version(options: AdditionalOptions) -> None:
    if not options.check_updates or options.ci_mode:
        return
    current_version = fuzzing_cli.__version__
    latest_version = get_latest_version()
    if latest_version is None:
        # failed to get the latest version, so skip the check this time
        return
    elif latest_version != current_version:
        msg = click.style(
            f"New version of fuzzing-cli is available: {latest_version}",
            "green",
            italic=True,
        )
        hint = click.style(
            "Please upgrade using `pip install --upgrade diligence-fuzzing` to get the latest features",
            "green",
            bold=True,
        )
        click.secho(f"{msg}\n{hint}")


__all__ = [
    "detect_ide",
    "get_latest_version",
    "check_latest_version",
]
