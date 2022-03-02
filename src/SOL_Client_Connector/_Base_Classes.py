# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import socket
from Crypto.PublicKey.RSA import RsaKey
from dataclasses import dataclass, field
from typing import Any

# Custom Packages

# ----------------------------------------------------------------------------------------------------------------------
# - File Object for Package -
# ----------------------------------------------------------------------------------------------------------------------
@dataclass
class BASE_Sol_File:
    hash_value:str
    filename_temp:str
    filename_transmission:str
    _filepath: str
    _filename:str
    filepath:property =  field(repr=False)
    filename:property =  field(repr=False)
    compression_level:int
    already_compressed:bool

    def cleanup(self)-> None:
        """clean up any remaining temp files"""
    def to_json(self) -> dict:
        """used by the json decoder to place the file_name string at the location of the Sol_File in the command structure"""
    def _buffer_size(self, object_size: int) -> int:
        """used to calculate the buffer size of file compression"""
    def compress_and_hash(self)->None:
        """compresses the file and stores them in temp folder"""

@dataclass
class BASE_SOL_Credentials:
    _username:str = field(repr=False)
    _password:str = field(repr=False)
    _password_new:str = field(repr=False)

    def dict(self) -> dict:
        """Forms the package to the server"""
    def to_json(self) -> str:
        """form dictionary to be placed in the eventual command"""

# ----------------------------------------------------------------------------------------------------------------------
# - DATA PACKAGE -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Package_Base:
    api_key_length = 128
    _api_key:str
    _commands:list
    _file_list:list
    _credentials:BASE_SOL_Credentials

    api_key:property
    commands:property
    file_list:property
    credentials:property

    def command_add(self,*args:dict) -> None:
        """Adds one or more commands to the command list"""
    def _iterateRecursion(self, dict_object: dict) -> None:
        """Method that used recursion to loop over the to be added command, to check if it has a SOL_File within it"""
    def pre_check(self) -> None:
        """runs methods that have to happen before the connection to the server is established"""
    def dict(self)-> dict:
        """Method to generate the correct data"""

# ----------------------------------------------------------------------------------------------------------------------
# - PACKAGE HANDLER -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Error(Exception):
    pass

class BASE_PackageHandler_Base:
    error=SOL_Error
    connection: socket.socket
    address: Any

    def _buffer_size(self, object_size: int) -> int:
        """returns a buffer size (10kb,100kb,1mb,...) to be used by file chunk readers"""
    def cleanup(self) -> None:
        """cleans up any data of the object"""
    def close(self) -> None:
        """closes the connection"""
    def wait_for_state(self, state: str) -> None:
        """Blocking wait for Client to send a state"""
    def wait_for_state_undefined(self) -> str:
        """Wait for an undefined state"""
    def wait_for_state_multiple(self, states: list) -> str:
        """Blocking wait for Client to send a state, and returns the correct state"""
    def send_state(self, state: str) -> None:
        """Send state to Client"""
    def _package_out(self, state: str, package_parameters: bytes, package_data: bytes) -> None:
        """Sends the package parameters and the entire package"""

class BASE_PackageHandler_File(BASE_PackageHandler_Base):
    def _file_package_handle_chunk(self, filepath_1: str, filepath_2: str, function_,file_handling_section: str) -> None:
        """Handle the transformation between file 1 and file 2 in chunks"""
    @staticmethod
    def file_package_parameters(session_key_encrypted: bytes = None,nonce: bytes = None,package_length: int = None,filename: str = None,hash_value: str = None) -> bytes:
        """Form file parameters to be sent to the client"""
    def file_package_output(self, state: str, file_object: BASE_Sol_File, client_public_key: RsaKey) -> None:
        """Send a file to the client"""
    def file_package_input(self, state: str, server_private_key: RsaKey) -> None:
        """Receive a file from the client"""

class BASE_PackageHandler_Data(BASE_PackageHandler_Base):
    @staticmethod
    def package_parameters(session_key_encrypted: bytes = None, tag: bytes = None, nonce: bytes = None, package_length:int=None) -> bytes:
        """Forms the package parameters and returns them as a dict in bytes"""
    @staticmethod
    def package_data(package_dict: dict) -> bytes:
        """forms the package into a bytes encoded dict"""

    def package_output_plain(self, state: str, package_dict: dict) -> None:
        """Sends a package which IS NOT encrypted"""
    def package_output_encrypted(self, state: str, package_dict: dict, client_public_key: RsaKey) -> None:
        """Sends a package which IS encrypted"""
    def package_input(self, state: str, server_private_key: RsaKey) -> dict:
        """Dependent on the incoming package parameters it will either pass the full package directly into a json or first decrypt it with the server's private key"""

class BASE_PackageHandler_Full(BASE_PackageHandler_Data, BASE_PackageHandler_File):
    pass

# ----------------------------------------------------------------------------------------------------------------------
# - CONNECTOR -
# ----------------------------------------------------------------------------------------------------------------------
class STOP_Error(Exception):
    pass

class SOL_Connector_Base:
    # Keys:
    _client_private_key: RsaKey
    _client_public_key: RsaKey
    _server_public_key: RsaKey

    address :   str
    port    :   int

    def connection_setup(self, address: str, port: int):
        """Insert address and port to connect to the API"""
    async def send(self, package: SOL_Package_Base) -> dict:
        """Send the actual data to the API by inserting the completed package"""
