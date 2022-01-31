# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import socket

# Custom Packages
from .PackageHandler_Data import PackageHandler_Data
from .PackageHandler_File import PackageHandler_File
from .._Base_Classes import BASE_PackageHandler_Full

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class PackageHandler_Full(BASE_PackageHandler_Full,PackageHandler_Data,PackageHandler_File):
    def __init__(self, connection:socket.socket):
        self.connection = connection
