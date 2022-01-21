# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import json
import hashlib

# Custom Packages
from .._Base_Classes import SOL_Package_Base, SOL_Error

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package(SOL_Package_Base):
    def __init__(self, api_key:str=None, credentials:dict=None):
        if api_key is None:
            self._api_key = None
        else:
            self.api_key = api_key

        if credentials is None:
            self._credentials = None
        else:
            self.credentials = credentials

    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value):
        if not isinstance(value, str) or len(value) != self.api_key_length:
            raise SOL_Error("API key was incorrectly defined")

        self._api_key = value

    # Credentials Setup
    @property
    def credentials(self):
        return self._credentials
    @credentials.setter
    def credentials(self, value):
        match value:
            case {"username": str(username),"password": str(password)}:
                self._credentials = {"username": username,"password": password}
            case _:
                raise SOL_Error("Credentials were incorrectly defined")

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------
    def package_api_key_request(self) -> bytes:
        # Check if we can form package
        if self.credentials is None:
            raise SOL_Error("Credentials weren't setup")

        # Form the package
        return json.dumps({
            "credentials": self.credentials
        }).encode("utf_8")

    def package(self,command_list:list) -> bytes:
        # Check if we can form package
        if self.api_key is None:
            raise SOL_Error("No API Key was setup")
        if not isinstance(command_list, list) and all(isinstance(i, dict) for i in command_list):
            raise SOL_Error("The Command List was incorrectly formatted")

        # Form the package
        return json.dumps({
            "api_key": self.api_key,
            "hash": {
                "q": hashlib.sha256(json.dumps(command_list).encode("utf_8")).hexdigest(),
                "api_key": hashlib.sha256(self.api_key.encode("utf_8")).hexdigest()
            },
            "q": command_list
        }).encode("utf_8")
