import datetime

from click.testing import CliRunner
from requests_mock import mock

from fuzzing_cli import __version__ as current_version
from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.storage import LocalStorage
from tests.common import write_config


def test_check_updates(
    api_key, tmp_path, fake_process, scribble_project, allow_updates_check
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )
    fake_process.register_subprocess([fake_process.any()], stdout="", occurrences=10)
    with mock() as m:
        m.register_uri(
            "GET",
            "https://pypi.org/pypi/diligence-fuzzing/json",
            json={"info": {"version": "0.0.1"}},
            headers={"ETag": "test-123"},
        )
        runner = CliRunner()
        runner.invoke(cli, ["arm"])
        # check for updates should not happen more than once in 1 day even if there are new versions
        result = runner.invoke(cli, ["arm"])

        assert m.call_count == 1

    assert result.exit_code == 0
    assert result.output == (
        "New version of fuzzing-cli is available: 0.0.1\n"
        "Please upgrade using `pip install --upgrade diligence-fuzzing` "
        "to get the latest features\n\n"
    )


def test_check_updates_etag(
    api_key, tmp_path, fake_process, scribble_project, allow_updates_check
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )
    fake_process.register_subprocess([fake_process.any()], stdout="", occurrences=10)
    LocalStorage.get_instance().set("latest_version", "0.0.1")
    LocalStorage.get_instance().set("latest_version_etag", "test-123")
    LocalStorage.get_instance().set(
        "latest_version_checked_at",
        (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=1, seconds=1)
        ).timestamp(),
    )
    with mock() as m:
        m.register_uri(
            "GET",
            "https://pypi.org/pypi/diligence-fuzzing/json",
            status_code=304,  # not modified
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["arm"])

        assert m.call_count == 1

    assert result.exit_code == 0
    assert result.output == (
        "New version of fuzzing-cli is available: 0.0.1\n"
        "Please upgrade using `pip install --upgrade diligence-fuzzing` "
        "to get the latest features\n\n"
    )

    assert LocalStorage.get_instance().get("latest_version") == "0.0.1"
    assert LocalStorage.get_instance().get("latest_version_etag") == "test-123"


def test_check_updates_etag_current_version(
    api_key, tmp_path, fake_process, scribble_project, allow_updates_check
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )
    fake_process.register_subprocess([fake_process.any()], stdout="", occurrences=10)
    LocalStorage.get_instance().set("latest_version", current_version)
    LocalStorage.get_instance().set("latest_version_etag", "test-123")
    LocalStorage.get_instance().set(
        "latest_version_checked_at",
        (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=1, seconds=1)
        ).timestamp(),
    )
    with mock() as m:
        m.register_uri(
            "GET",
            "https://pypi.org/pypi/diligence-fuzzing/json",
            status_code=304,  # not modified
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["arm"])

        assert m.call_count == 1

    assert result.exit_code == 0
    assert result.output == "\n"

    assert LocalStorage.get_instance().get("latest_version") == current_version
    assert LocalStorage.get_instance().get("latest_version_etag") == "test-123"


def test_check_updates_etag_new_version(
    api_key, tmp_path, fake_process, scribble_project, allow_updates_check
):
    write_config(
        config_path=f"{tmp_path}/.fuzz.yml", base_path=str(tmp_path), **scribble_project
    )
    fake_process.register_subprocess([fake_process.any()], stdout="", occurrences=10)
    LocalStorage.get_instance().set("latest_version", "0.0.1")
    LocalStorage.get_instance().set("latest_version_etag", "test-123")
    LocalStorage.get_instance().set(
        "latest_version_checked_at",
        (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=1, seconds=1)
        ).timestamp(),
    )
    with mock() as m:
        m.register_uri(
            "GET",
            "https://pypi.org/pypi/diligence-fuzzing/json",
            json={"info": {"version": "0.0.2"}},
            headers={"ETag": "test-456"},
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["arm"])

        assert m.call_count == 1

    assert result.exit_code == 0
    assert result.output == (
        "New version of fuzzing-cli is available: 0.0.2\n"
        "Please upgrade using `pip install --upgrade diligence-fuzzing` "
        "to get the latest features\n\n"
    )

    assert LocalStorage.get_instance().get("latest_version") == "0.0.2"
    assert LocalStorage.get_instance().get("latest_version_etag") == "test-456"
