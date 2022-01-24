# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json

# Custom Packages
from .._Base_Classes import SOL_Package_Base, SOL_Error

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package(SOL_Package_Base):
    def __init__(self, api_key:str=None, credentials:dict=None, first_api_key_request:bool=False):
        if api_key is None:
            self._api_key = None
        else:
            self.api_key = api_key

        if credentials is None:
            self._credentials = None
        else:
            self.credentials = credentials

        # when not defined on init, it will be false, so no check is needed here
        self.first_api_key_request = first_api_key_request

        self._commands = []


    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value:str):
        if not isinstance(value, str) or len(value) != self.api_key_length:
            raise SOL_Error(4402, "API key was incorrectly defined")

        self._api_key = value

    # Credentials Setup
    @property
    def credentials(self):
        return self._credentials
    @credentials.setter
    def credentials(self, value:dict):
        match value:
            case {"username": str(username),"password": str(password)}:
                self._credentials = {"username": username,"password": password}
            case _:
                raise SOL_Error(4403, "Credentials were incorrectly defined")

    # Request for the User's first API key
    @property
    def first_api_key_request(self):
        return self._first_api_key_request
    @first_api_key_request.setter
    def first_api_key_request(self, value:bool):
       if not isinstance(value, bool):
           raise SOL_Error(4404, "Request for a first API Key can only be a boolean value")
       if self.credentials is None and value:
           raise SOL_Error(4404, "Credentials have to be given for a first API key Request")

       self._first_api_key_request = value

    # ------------------------------------------------------------------------------------------------------------------
    # - Command List Formation -
    # ------------------------------------------------------------------------------------------------------------------
    @property
    def commands(self):
        return self._commands

    def command_add(self,*args:dict):
        if all((len(c) == 1 and isinstance(c, dict)) for c in args):
            self._commands = self.commands + list(args)
        else:
            raise SOL_Error(4405, "Unable to insert the command(s)")

    def commands_clear(self):
        self._commands = []

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------
    def data(self) -> bytes:
        # If there are more edge cases for special packages, they should be checked here
        if self.first_api_key_request:
            return self._package_api_key_request()
        else:
            return self._package()

    def _package_api_key_request(self) -> bytes:
        # Check if we can form package
        if self.credentials is None:
            raise SOL_Error(4403, "Credentials weren't setup")

        # Form the package
        return json.dumps({
            "credentials": self.credentials
        }).encode("utf_8")

    def _package(self) -> bytes:
        # Check if we can form package
        if self.api_key is None:
            raise SOL_Error(4402, "No API Key was setup")

        if len(self.commands) == 0:
            raise SOL_Error(4402, "No commands were set up")

        # Form the package
        try:
            return json.dumps({
                "api_key": self.api_key,
                "q": self.commands
            }).encode("utf_8")

        except (json.JSONDecodeError,TypeError) as e:
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following error:\n{e}")

