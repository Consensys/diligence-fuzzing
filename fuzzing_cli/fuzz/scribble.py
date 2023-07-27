import json
import os
import subprocess
from typing import List, Optional, Tuple

from fuzzing_cli.util import sol_files_by_directory

SCRIBBLE_ARMING_META_FILE = ".scribble-arming.meta.json"


class ScribbleMixin:
    """A mixing for job objects to instrument code with Scribble."""

    @staticmethod
    def _handle_scribble_error(
        process: subprocess.CompletedProcess,
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Handle scribble subprocess errors.

        This method will throw a CLI error in the case of scribble exiting
        with a non-zero exit code.

        :param process: The finished scribble process object
        """
        if process.returncode == 0:
            return 0, process.stdout.decode(), None

        return process.returncode, process.stdout.decode(), process.stderr.decode()

    def instrument_solc_file(
        self, target: str, scribble_path: str, remappings: Tuple[str]
    ) -> dict:
        """Instrument a single Solidity file with scribble.

        :param target: The target filename to pass to scribble
        :param scribble_path: The path to the scribble executable
        :param remappings: Optional solc import remappings
        :return: The deserialized scribble JSON output object
        """
        process = subprocess.run(
            [scribble_path, "--input-mode=source", "--output-mode=json"]
            + ([f"--path-remapping={';'.join(remappings)}"] if remappings else [])
            + [target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._handle_scribble_error(process)

        return json.loads(process.stdout.decode())

    @staticmethod
    def instrument_solc_in_place(
        file_list: List[str],
        scribble_path: str,
        remappings: List[str] = None,
        solc_version: str = None,
        no_assert: bool = False,
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Instrument a collection of Solidity files in place.

        :param no_assert: If set execution will not halt when an invariant is violated (only an event will be emitted)
        :param file_list: List of paths to Solidity files to instrument
        :param scribble_path: The path to the scribble executable
        :param remappings: List of import remappings to pass to solc
        :param solc_version: The solc compiler version to use
        """
        command = [
            scribble_path,
            "--arm",
            "--output-mode=files",
            f"--instrumentation-metadata-file={SCRIBBLE_ARMING_META_FILE}",
            "--debug-events",
        ]

        if remappings:
            command.append(f"--path-remapping={';'.join(remappings)}")

        if solc_version:
            command.append(f"--compiler-version={solc_version}")

        if no_assert:
            command.append(f"--no-assert")

        # Scribble doesn't currently support directories as inputs
        # so we create a list of all solidity files inside each of the targets
        # and submit that to Scribble.

        sol_files = []
        for file in file_list:
            target_files = sol_files_by_directory(file)
            sol_files = [*sol_files, *target_files]

        if len(sol_files) == 0:
            return 1, None, "No files to instrument at provided targets"

        command.extend(sol_files)

        process = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        return ScribbleMixin._handle_scribble_error(process)

    @staticmethod
    def disarm_solc_in_place(
        file_list: List[str], scribble_path: str
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Un-instrument a collection of Solidity files in place.

        :param scribble_path: The path to the scribble executable
        """
        command = [
            scribble_path,
            "--disarm",
            f"--instrumentation-metadata-file={SCRIBBLE_ARMING_META_FILE}",
        ]
        sol_files = []
        for file in file_list:
            target_files = sol_files_by_directory(file)
            sol_files = [*sol_files, *target_files]

        if len(sol_files) == 0:
            return 1, None, "No files to instrument at provided targets"

        command.extend(sol_files)

        process = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        return ScribbleMixin._handle_scribble_error(process)

    @staticmethod
    def get_arming_instr_meta():
        if os.path.exists(SCRIBBLE_ARMING_META_FILE):
            with open(SCRIBBLE_ARMING_META_FILE, "r") as f:
                return json.load(f)

        return None
