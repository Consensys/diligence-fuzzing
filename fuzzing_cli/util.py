import logging
import os
import shutil
from pathlib import Path
from typing import AnyStr, List

import click

LOGGER = logging.getLogger("fuzzing-cli")


def sol_files_by_directory(target_path: Path) -> List[Path]:
    """Gathers all the .sol files inside the target path
    including sub-directories and returns them as a List.
    Non .sol files are ignored.

    :param target_path: The directory to look for .sol files
    :return:
    """
    return files_by_directory(target_path, ".sol")


def files_by_directory(target_path: Path, extension: AnyStr) -> List[Path]:
    """Gathers all the target extension files inside the target path
    including sub-directories and returns them as a List.
    Non target extension files are ignored.

    :param target_path: The directory to look for target extension files
    :return:
    """
    target_files = []
    # We start by checking if the target_path is potentially a target extension file
    if target_path.name.endswith(extension):
        # If target extension file we check if the target exists or if it's a user input error
        if not target_path.is_file():
            raise click.exceptions.UsageError(
                "Could not find "
                + str(target_path)
                + ". Did you pass the correct directory?"
            )
        else:
            """If it's a valid target extension file there is no need to search further and we just append it to our
            list to be returned, removing the .original extension, leaving only the .sol
            """
            target_files.append(
                target_path.parent.joinpath(target_path.name.replace(".original", ""))
            )
    source_dir = os.walk(target_path)
    for sub_dir in source_dir:
        if len(sub_dir[2]) > 0:
            # sub directory with target extension files
            file_prefix = sub_dir[0]
            for file in sub_dir[2]:  # type: str
                if file.startswith("."):  # hidden file
                    continue
                if "__scribble_" in file:
                    LOGGER.debug(f"Skipped for being a scribble file {file}")
                    continue

                if not file.endswith(extension):
                    LOGGER.debug(f"Skipped for not being a solidity file: {file}")
                    continue

                file_name = Path(file_prefix).joinpath(file)
                LOGGER.debug(f"Found target extension file: {file_name}")
                # We remove the .original extension, added by Scribble

                target_files.append(
                    file_name.parent.joinpath(file_name.name.replace(".original", ""))
                )
    return target_files


def get_content_from_file(file_path: Path) -> AnyStr:
    reader = open(file_path)
    try:
        source_code = reader.read()
    finally:
        reader.close()
    return source_code


def executable_command(exec_path: str) -> List[str]:
    """Get the executable command

    :param exec_path: The path to the executable
    """
    if Path(exec_path).is_file():
        # it's a full path to the executable
        return [exec_path]

    # exec_path can be an executable in the PATH or a command with arguments
    resolved_exec_path = shutil.which(exec_path)
    if resolved_exec_path is not None:
        # it's a command in the PATH resolved by shutil
        return [resolved_exec_path]

    if exec_path.count(" ") > 0:
        # it's a command with arguments. Split it and return the list
        return [c.strip() for c in exec_path.split(" ")]

    # we can't resolve the full executable path, so we assume
    # it's a command in the PATH and return the list
    return [exec_path]
