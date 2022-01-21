# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import socket

# Custom Packages

# ----------------------------------------------------------------------------------------------------------------------
# - DATA PACKAGE -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package_Base:
    api_key_length = 128
    _api_key:str
    _credentials:dict
    _q_list:list #todo ?

    # ------------------------------------------------------------------------------------------------------------------
    # - Properties and Checks of to be inserted Data -
    # ------------------------------------------------------------------------------------------------------------------
    # Api Key setup
    @property
    def api_key(self):
        return self._api_key
    @api_key.setter
    def api_key(self, value):
        """Some checks for the correct insertion of the API key"""
    # Credentials Setup
    @property
    def credentials(self):
        return self._credentials
    @credentials.setter
    def credentials(self, value):
        """Some checks for the correct insertion of the credentials"""

    # ------------------------------------------------------------------------------------------------------------------
    # - Package Formations -
    # ------------------------------------------------------------------------------------------------------------------
    def package_api_key_request(self) -> bytes:
        """Forms the Correct package to retrieve the user's first API Key in the format of a json dump to string"""

    def package(self,command_list:list) -> bytes:
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

    def __init__(self):
        self.ciphers = SOL_Connector_Ciphers_Base()

    def connection_setup(self, address: str, port: int) -> bool:
        """Insert address abd port to connect to the API"""

# ----------------------------------------------------------------------------------------------------------------------
# - ENCRYPTION -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector_Ciphers_Base:
    _c: SOL_Connector_Base