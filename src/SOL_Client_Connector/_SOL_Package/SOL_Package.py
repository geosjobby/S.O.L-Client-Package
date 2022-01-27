# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json

# Custom Packages
from .._Base_Classes import SOL_Package_Base, SOL_Error
from .SOL_File_Object import SOL_File

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package(SOL_Package_Base):
    def __init__(self, api_key:str=None, credentials:dict=None, first_api_key_request:bool=False):
        # Set default var
        self._api_key = None
        self._credentials = None
        self._commands = []
        self._file_list = []

        # Check if immediate input was given
        if api_key is not None:
            self.api_key = api_key
        if credentials is not None:
            self.credentials = credentials

        # has to be set after everything else, depends on self._api_key and self._credentials
        self.first_api_key_request = first_api_key_request

    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value:str):
        if not isinstance(value, str) \
        or len(value) != self.api_key_length:
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
    def command_add(self,*args:dict) -> None:
        if not all((len(c) == 1 and isinstance(c, dict)) for c in args):
            raise SOL_Error(4405, "Unable to insert the command(s)")
        self._commands = self.commands + list(args)

        # check for file presence
        for c in list(args):
            self._iterateRecursion(c)

    def _iterateRecursion(self, dict_object: dict) -> None:
        for _, v in dict_object.items():
            if isinstance(v, SOL_File):
                self._file_list.append(v)
            elif isinstance(v, dict):
                self._iterateRecursion(v) # the few times in a year that I use recursion

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------
    def dict(self) -> dict:
        # If there are more edge cases for special packages, they should be checked here
        return self._package_api_key_request() if self.first_api_key_request else self._package()

    def _package_api_key_request(self) -> dict:
        # Check if we can form package
        if self.credentials is None:
            raise SOL_Error(4403, "Credentials weren't setup")
        # Form the package
        return {"credentials": self.credentials}

    def _package(self) -> dict:
        # Check if we can form package
        if self.api_key is None:
            raise SOL_Error(4402, "No API Key was setup")
        if len(self.commands) == 0:
            raise SOL_Error(4402, "No commands were set up")

        # Form the package
        return{"api_key": self.api_key,"q": self.commands}