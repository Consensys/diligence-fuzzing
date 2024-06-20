#
# FaaS Client Errors
#
import click.exceptions


class FaaSError(Exception):
    """Base class for FaaS module exceptions"""

    def __init__(self, message, detail=None):
        self.message = message
        self.detail = detail

    pass


class EmptyArtifactsError(Exception):
    pass


class AuthorizationError(FaaSError):
    pass


# HTTP Requests


class RequestError(FaaSError):
    """Exception raised for errors with the http connection to the faas"""

    pass


class BadStatusCode(RequestError):
    """Exception raised for http responses with a bad status code"""

    pass


# Data Formats


class PayloadError(FaaSError):
    """Exception raised for errors extracting data from the provided payload"""

    pass


class ScribbleMetaError(FaaSError):
    """Exception raised for errors getting the Scribble Metadata"""

    pass


class ScribbleError(click.exceptions.ClickException):
    """Raised when `scribble` command fails"""

    def __init__(self, underlying_error: Exception):
        self.message = f"""Scribble not installed or configured correctly.

It appears that Scribble is not installed or configured correctly on your system.

You may need to:
  - install Scribble
  - ensure that the Scribble executable is in your PATH
  - consider providing Scribble executable path using `--scribble-path` argument to command or set it in the config (https://github.com/Consensys/diligence-fuzzing/blob/master/docs/configuration.md#arming-configuration-options)
  - Note: Windows users may need to use the full path to the Scribble executable (e.g. "node .\\node_modules\\eth-scribble\\dist\\bin\\scribble.js")

Please ensure that Scribble is installed and configured correctly before attempting to run the fuzzer again. If the issue persists, please consult the Scribble documentation at https://docs.scribble.codes/tool/installation.

Underlying error: {underlying_error}
"""

    pass


class CreateFaaSCampaignError(FaaSError):
    """Exception raised for errors creating the FaaS Campaign"""

    pass


#
# RPC client
#


class RPCCallError(click.exceptions.ClickException):
    """Exception raised when there is an error calling the RPC endpoint"""

    pass


class SeedStateError(FaaSError):
    """Exception raised when there is an error generating the seed state"""

    pass


class BrownieError(FaaSError):
    """Base class for Brownie Job exceptions"""

    pass


class BuildArtifactsError(click.exceptions.ClickException):
    """Exception raised for errors fetching the build artifacts"""

    pass


class QuickCheckError(click.exceptions.ClickException):
    pass


class FuzzingLessonsError(click.exceptions.ClickException):
    pass


class SourceError(BrownieError):
    """Exception raised for errors the source and AST of a source file"""

    pass


#
#   Foundry
#


class ForgeError(click.exceptions.ClickException):
    """Exception raised when we have issues calling Forge."""

    pass


_windows_hint = (
    "Note: Windows users may need to use the full path to the "
    'Foundry executable (e.g. "C:\\AppData\\foundry\\forge")'
)


class ForgeConfigError(ForgeError):
    """Raised when `forge config` command fails"""

    def __init__(self, underlying_error: Exception):
        self.message = f"""Foundry not installed or configured correctly.

It appears that Foundry is not installed or configured correctly on your system. This error is preventing the fuzzer from running as expected.

Please ensure that Foundry is installed and configured correctly before attempting to run the fuzzer again. If the issue persists, please consult the Foundry documentation or seek help from the Foundry community.

{_windows_hint}

Underlying error: {underlying_error}
"""

    pass


class ForgeCompilationError(ForgeError):
    """Raised when `forge config` command fails"""

    def __init__(self, underlying_error: Exception):
        self.message = f"""Unable to compile Foundry project.

It appears that there are issues with compiling the Foundry project. This error is likely related to the project's code or configuration.

Please check the project's compilation logs or consult the project's documentation or support resources for assistance with resolving any compilation issues. Once the project has been successfully compiled, you can attempt to run the fuzzer again.

{_windows_hint}

Underlying error: {underlying_error}
"""

    pass


class ForgeNotFoundryDirectory(ForgeError):
    """Raised when `forge config` command fails"""

    def __init__(self):
        self.message = """Unable to collect Foundry tests.

There was an issue collecting Foundry tests. We weren't able to find a foundry.toml file in this directory, which points to this not being a Foundry project root folder.

Please ensure that the Foundry project is properly configured and that the 'forge test' command can be executed correctly and displays the expected test results.
"""

    pass


class ForgeNoTestsFoundError(ForgeError):
    """Raised when `forge config` command fails"""

    def __init__(self):
        self.message = """Unable to collect Foundry tests.

It appears that there was an issue collecting Foundry tests. This error is likely caused by the Foundry project not having any tests.

Please ensure that the Foundry project is properly configured and that the 'forge test' command can be executed correctly and displays the expected test results.
"""

    pass


class ForgeCollectTestsError(ForgeError):
    """Raised when `forge config` command fails"""

    def __init__(self, underlying_error: Exception):
        self.message = f"""Unable to collect Foundry tests.

It appears that there was an issue collecting Foundry tests with the 'forge test --list' command. This error may be related to issues with the Foundry project configuration or the command itself.

Please ensure that the Foundry project is properly configured and that the 'forge test --list' command can be executed correctly. You may want to consult the Foundry documentation or seek help from the Foundry community for further assistance.

{_windows_hint}

Underlying error: {underlying_error}
"""

    pass
