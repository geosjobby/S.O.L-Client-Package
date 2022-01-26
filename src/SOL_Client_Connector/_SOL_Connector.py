# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import socket
import base64
import sys
import os

from Crypto.PublicKey.RSA import RsaKey

# Custom Structure
from ._Base_Classes import SOL_Connector_Base, SOL_Error, SOL_Package_Base
from ._SOL_Package import (
    SOL_File,
    pp_encrypt,        # Encryption and decryption related functions
    pp_import_key,
    pp_decrypt,
    pp_generate_keys
)

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
# https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable#:~:text=Just%20add%20to_json,in%20your%20project.
# MAGIC, which makes the to_json method of the File_Object work:
def _default_Encode(self, obj):
    return getattr(obj.__class__, "to_json", _default_Encode.default)(obj)
_default_Encode.default = json.JSONEncoder().default
json.JSONEncoder.default = _default_Encode


# ----------------------------------------------------------------------------------------------------------------------
# - SOL Connector Class -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector(SOL_Connector_Base):
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # ------------------------------------------------------------------------------------------------------------------
    # - Connection Setup and connection waiting-
    # ------------------------------------------------------------------------------------------------------------------
    def connection_setup(self, address:str, port:int):
        if not isinstance(address, str):
            raise SOL_Error(4401, "Address was not defined as a string")
        if not isinstance(port, int):
            raise SOL_Error(4401, "Port was not defined as an integer")
        self.address = address
        self.port = port

    def _wait_for_state(self, state:str):
        match self.socket.recv(1024).decode("utf_8"):
            case s if s == state:
                return
            case "":
                raise SOL_Error(4103, f"Connection became unavailable")
            case a:
                raise SOL_Error(4103, f"Connection became unavailable, unexpected command: {a}")

    def _send_state(self, state: str):
        self.socket.send(state.encode("utf_8"))

    # ------------------------------------------------------------------------------------------------------------------
    # - Package OUTGOING Handlers -
    # ------------------------------------------------------------------------------------------------------------------
    def _package_out_handle(self, public_key: RsaKey, package_data:bytes):
        # 1. Encrypt the package
        encrypted_package, session_key_encrypted, tag, nonce = pp_encrypt( # type: bytes,bytes,bytes,bytes
            package_data, public_key
        )

        # 3. send message parameters
        self.socket.sendall(b":".join([base64.b64encode(a) for a in [
            session_key_encrypted,
            tag,
            nonce,
            str(sys.getsizeof(encrypted_package)).encode("utf_8")
        ]]))

        # 4. Send the entire package if we get the all clear
        self._wait_for_state("SOL_CLEAR")
        self.socket.sendall(encrypted_package)

    def _package_out_handle_file(self, public_key:RsaKey, file:SOL_File):
        # Send File parameters
        self._wait_for_state("SOL_FILE_PARAM")
        self._package_out_handle(
            public_key,
            json.dumps({
                "file_name": file.filename_temp,
                "file_size": os.path.getsize(f"temp/{file.filename_temp}")
            }).encode("utf_8")
        )

        # Send File
        self._wait_for_state("SOL_FILE")
        with open(f"temp/{file.filename_temp}", "rb") as f:
            self._package_out_handle(
                public_key,
                f.read(),  # as the file is already in bytes, no need to encode
            )

    # ------------------------------------------------------------------------------------------------------------------
    # - Package INCOMING Handlers -
    # ------------------------------------------------------------------------------------------------------------------
    def _package_in_handle(self, private_key: RsaKey)-> list:
        session_key_encrypted, tag, nonce, package_length = ( # type: bytes,bytes,bytes,bytes,bytes
            base64.b64decode(a) for a in self.socket.recv(1024).split(b":")
        )

        package_length = int(package_length.decode("utf_8"))
        if package_length <= 0:
            raise SOL_Error(4103, "Connection became unavailable")
        self._send_state("CLIENT_CLEAR")

        q_data_encrypted = b""
        while len(q_data_encrypted) < package_length:
            q_data_encrypted += self.socket.recv(2048)

        # 4. decrypt the package and form the reply list
        return json.loads(
            pp_decrypt(q_data_encrypted, private_key, session_key_encrypted, tag, nonce).decode("utf_8")
        )["r"]

    def _package_in_handle_file(self, private_key: RsaKey, file_param:dict):
        session_key_encrypted, tag, nonce, _ = ( # type: bytes,bytes,bytes,bytes,bytes
            base64.b64decode(a) for a in self.socket.recv(1024).split(b":")
        )
        self._send_state("CLIENT_CLEAR")

        # todo handle the file file

    # ------------------------------------------------------------------------------------------------------------------
    # - MAIN COMMAND -
    # ------------------------------------------------------------------------------------------------------------------
    def send(self, package:SOL_Package_Base)->list[list]:
        try:
            # check the package is the correct format
            if not isinstance(package, SOL_Package_Base):
                raise SOL_Error(4101, "Package was not defined as a SOL_Package Object")

            # form package data before we ask to connect to server as the
            package_data = package.data()

            # Connect to API server and send data
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(60000)

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # 1. Send request for public key
            self._send_state("SOL_KEY")
            match self.socket.recv(1024):
                case b"5555":  # API unavailable at the server level and will not be able to send a reply back
                    raise SOL_Error(5555, "API server is unavailable, at the server level.\nIt did connect to the correct server location, but the actual API Server has crashed")
                case bytes(public_key_str):
                    public_key = pp_import_key(public_key_str)
                    self._send_state("SOL_KEY_INGESTED")
                case _:
                    raise SOL_Error(4104, "No connection could be established to the server")

            # 2. Send package with commands
            self._wait_for_state("SOL_COMMANDS")
            self._package_out_handle(
                public_key,
                package_data
            )
            self._wait_for_state("SOL_COMMANDS_INGESTED")

            # 3. Check if files need to be sent
            for file in package.file_list: # type: SOL_File
                # Send server that we have files to upload
                self._send_state("CLIENT_FILE")
                # Send File Package
                self._package_out_handle_file(
                    public_key,
                    file
                )
                # Wait for ingested result
                self._wait_for_state("SOL_FILE_INGESTED")

            # 4. after all files have been handled, stop the file upload
            self._send_state("CLIENT_STOP")

            # ----------------------------------------------------------------------------------------------------------
            # grab the reply package
            # ----------------------------------------------------------------------------------------------------------
            # 1. Receive request for public key:
            private_key, public_key = pp_generate_keys()
            self._wait_for_state("CLIENT_KEY")
            self.socket.sendall(public_key.exportKey())
            self._wait_for_state("CLIENT_KEY_RECEIVED")

            # 2. assemble the actual package data
            self._send_state("CLIENT_COMMANDS_RESULT")
            result = self._package_in_handle(private_key)
            self._send_state("CLIENT_COMMANDS_RESULT_INGESTED")

            # 3. ASk for files:
            while True:
                match self.socket.recv(1024).decode("utf_8"):
                    case "SOL_FILE":
                        raise SOL_Error("NO SOL_FILE Ingesting client side defined") # todo

                    case "SOL_STOP" | _:
                        break

            # 4. CLEANUP
            for f in package.file_list:  # type: SOL_File
                f.cleanup()

            # 4. Return Command list
            return result

        # if anything goes wrong, it should be excepted here so the entire program doesn't crash
        except socket.timeout:
            raise SOL_Error(4103,"Connection became unavailable")
        except json.JSONDecodeError as e:
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")