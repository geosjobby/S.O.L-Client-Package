# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import socket

# Custom Packages

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