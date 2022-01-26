# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import socket
from Crypto.PublicKey.RSA import RsaKey
import os
from dataclasses import dataclass
import zlib
import base64

# Custom Packages

# ----------------------------------------------------------------------------------------------------------------------
# - File Object for Package -
# ----------------------------------------------------------------------------------------------------------------------
@dataclass
class SOL_File_Base:
    filename_temp:str
    buffer_size:int
    _filepath: str
    _filename:str
    filepath:property
    filename:property

    @property
    def filepath(self):
        return self._filepath

    @filepath.setter
    def filepath(self, filepath: str):
        """file_path setter with the check if the file exists"""

    @property
    def filename(self):
        return self._filename

# ----------------------------------------------------------------------------------------------------------------------
# - DATA PACKAGE -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package_Base:
    api_key_length = 128
    _api_key:str
    _credentials:dict
    _commands:list
    _first_api_key_request:bool
    _file_list:list

    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value:str):
        """Some checks for the correct insertion of the API key"""
    # Credentials Setup
    @property
    def credentials(self):
        return self._credentials
    @credentials.setter
    def credentials(self, value:dict):
        """Some checks for the correct insertion of the credentials"""
    # Request for the User's first API key
    @property
    def first_api_key_request(self):
        return self._first_api_key_request
    @first_api_key_request.setter
    def first_api_key_request(self, value:bool):
        """Enable or disable request for the User's first API key"""

    # ------------------------------------------------------------------------------------------------------------------
    # - Command List Formation -
    # ------------------------------------------------------------------------------------------------------------------
    @property
    def commands(self) -> list:
        return self._commands
    @property
    def file_list(self) -> list[SOL_File_Base]:
        return self._file_list

    def command_add(self,*args:dict) -> None:
        """Adds one or more commands to the command list"""

    def _iterateRecursion(self, dict_object: dict) -> None:
        """Method that used recursion to loop over the to be added command, to check if it has a SOL_File within it"""

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------

    def data(self)-> bytes:
        """Method to generate the correct data"""

    def _package_api_key_request(self) -> bytes:
        """Forms the Correct package to retrieve the user's first API Key in the format of a json dump to string"""

    def _package(self) -> bytes:
        """Forms the Correct package structure to execute the commands by the API"""

# ----------------------------------------------------------------------------------------------------------------------
# - CONNECTOR -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Error(Exception):
    pass

class SOL_Connector_Base:
    socket  :   socket.socket
    address :   str
    port    :   int
    error   =   SOL_Error

    def connection_setup(self, address: str, port: int):
        """Insert address and port to connect to the API"""

    async def send(self, package: SOL_Package_Base) -> list[list]:
        """Send the actual data to the API by inserting the completed package"""
