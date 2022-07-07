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
