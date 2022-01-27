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

    def _wait_for_state_multiple(self, states:list):
        state = self.socket.recv(1024).decode("utf_8")
        if state not in states:
            raise self.error(4103)
        return state

    def _send_state(self, state: str):
        self.socket.send(state.encode("utf_8"))

        # ------------------------------------------------------------------------------------------------------------------
    # - Form Package and parameters -
    # ------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def package_parameters(session_key_encrypted: bytes = None, tag: bytes = None, nonce: bytes = None,package_length: int = None) -> bytes:
        return json.dumps({
            "sske": base64.b64encode(session_key_encrypted).decode("utf8"),
            "tag": base64.b64encode(tag).decode("utf8"),
            "nonce": base64.b64encode(nonce).decode("utf8"),
            "len": package_length,
        }).encode("utf8")

    @staticmethod
    def package_data(package_dict: dict) -> bytes:
        return json.dumps(package_dict).encode("utf_8")

    # ------------------------------------------------------------------------------------------------------------------
    # - Default Packages outgoing -
    # ------------------------------------------------------------------------------------------------------------------
    def _package_out(self, state: str, package_parameters: bytes, package_data: bytes):
        # Send parameters
        self._send_state(f"{state}_PARAM")
        self._wait_for_state(f"{state}_PARAM_READY")
        self.socket.sendall(package_parameters)
        self._wait_for_state(f"{state}_PARAM_INGESTED")

        # Send package
        self.socket.sendall(package_data)
        self._wait_for_state(f"{state}_PACKAGE_INGESTED")

    def package_out_plain(self, state: str, package_dict: dict) -> None:
        # assemble the package bytes
        package_data = self.package_data(package_dict)
        # Encrypt package
        # /
        # assemble package parameters
        package_parameters = self.package_parameters(None, None, None, len(package_data))
        # send the data
        self._package_out(state, package_parameters, package_data)

    def package_out_encrypted(self, state: str, package_dict: dict, server_public_key: RsaKey) -> None:
        # assemble the package bytes
        package_data = self.package_data(package_dict)
        # Encrypt package
        encrypted_package, session_key_encrypted, tag, nonce = pp_encrypt(
            package_data,
            server_public_key
        )
        # assemble package parameters
        package_parameters = self.package_parameters(session_key_encrypted, tag, nonce, len(encrypted_package))
        # send the data
        self._package_out(state, package_parameters, encrypted_package)

    # ------------------------------------------------------------------------------------------------------------------
    # - Default Packages incoming -
    # ------------------------------------------------------------------------------------------------------------------
    def package_in_plain_and_encrypted(self, state: str, client_private_key: RsaKey) -> dict:
        self._wait_for_state(f"{state}_PARAM")
        self._send_state(f"{state}_PARAM_READY")
        package_param_dict = json.loads(self.socket.recv(10240).decode("utf_8"))
        match package_param_dict:

            # unencrypted package
            case {"sske": None, "tag": None, "nonce": None, "len": int(package_length)}:
                # Ingest all the parameters
                self._send_state(f"{state}_PARAM_INGESTED")

                # Ingest the package
                package_data = b""
                while sys.getsizeof(package_data) < package_length:
                    package_data += self.socket.recv(1048576)
                self._send_state(f"{state}_PACKAGE_INGESTED")

                # Decrypt the package
                # /

                # Decode the package
                package_dict = json.loads(package_data.decode("utf_8"))
                return package_dict

            # encrypted package
            case {"sske": str(sske), "tag": str(tag), "nonce": str(nonce), "len": int(package_length)}:
                # Ingest all the parameters
                session_key_encrypted = base64.b64decode(sske.encode("utf8"))
                tag = base64.b64decode(tag.encode("utf8"))
                nonce = base64.b64decode(nonce.encode("utf8"))
                self._send_state(f"{state}_PARAM_INGESTED")

                # Ingest the package
                package_data_encrypted = b""
                while sys.getsizeof(package_data_encrypted) < package_length:
                    package_data_encrypted += self.socket.recv(1048576)
                self._send_state(f"{state}_PACKAGE_INGESTED")

                # Decrypt the package
                package_data = pp_decrypt(
                    package_data_encrypted,
                    client_private_key,
                    session_key_encrypted,
                    tag,
                    nonce
                )

                # Decode the package
                package_dict = json.loads(package_data.decode("utf_8"))
                return package_dict

    # ------------------------------------------------------------------------------------------------------------------
    # - MAIN COMMAND -
    # ------------------------------------------------------------------------------------------------------------------
    def send(self, package:SOL_Package_Base)->list[list]:
        try:
            # check the package is the correct format
            if not isinstance(package, SOL_Package_Base):
                raise SOL_Error(4101, "Package was not defined as a SOL_Package Object")

            # form package data before we ask to connect to server as the
            package_dict = package.dict()
            client_private_key, client_public_key = pp_generate_keys()

            # Connect to API server and send data
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(60000)

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------

            # 1. Send request for public key
            self._send_state("SOL_KEY")
            key_dict = self.package_in_plain_and_encrypted("KEY",client_private_key)
            server_public_key = pp_import_key(key_dict["key"])

            # 2. Send API KEY
            self._wait_for_state("API_KEY")
            self.package_out_encrypted(
                state="API_KEY",
                package_dict={"api_key":package.api_key},
                server_public_key=server_public_key
            )

            # 3. Wait for API key to be validated
            match self._wait_for_state_multiple(["API_KEY_OK", "STOP"]):
                case "STOP": # API KEY was invalid
                    return [[4103,None]]
                case "API_KEY_OK":
                    pass
                case _:
                    return [[5000, None]]

            # 4. Send commands
            self._wait_for_state("CLIENT_COMMANDS")
            self.package_out_encrypted(
                state="CLIENT_COMMANDS",
                package_dict=package_dict,
                server_public_key=server_public_key
            )





            # match self.socket.recv(1024):
            #     case b"5555":  # API unavailable at the server level and will not be able to send a reply back
            #         raise SOL_Error(5555, "API server is unavailable, at the server level.\nIt did connect to the correct server location, but the actual API Server has crashed")
            #     case bytes(server_public_key_str):
            #         server_public_key = pp_import_key(server_public_key_str)
            #         self._send_state("SOL_KEY_INGESTED")
            #     case _:
            #         raise SOL_Error(4104, "No connection could be established to the server")
            #
            # # 2. Send package with commands
            # self._wait_for_state("SOL_COMMANDS")
            # self._package_out_handle(
            #     public_key,
            #     package_data
            # )
            # self._wait_for_state("SOL_COMMANDS_INGESTED")
            #
            # # 3. Check if files need to be sent
            # for file in package.file_list: # type: SOL_File
            #     # Send server that we have files to upload
            #     self._send_state("CLIENT_FILE")
            #     # Send File Package
            #     self._package_out_handle_file(
            #         public_key,
            #         file
            #     )
            #     # Wait for ingested result
            #     self._wait_for_state("SOL_FILE_INGESTED")
            #
            # # 4. after all files have been handled, stop the file upload
            # self._send_state("CLIENT_STOP")
            #
            # # ----------------------------------------------------------------------------------------------------------
            # # grab the reply package
            # # ----------------------------------------------------------------------------------------------------------
            # # 1. Receive request for public key:
            # private_key, public_key = pp_generate_keys()
            # self._wait_for_state("CLIENT_KEY")
            # self.socket.sendall(public_key.exportKey())
            # self._wait_for_state("CLIENT_KEY_RECEIVED")
            #
            # # 2. assemble the actual package data
            # self._send_state("CLIENT_COMMANDS_RESULT")
            # result = self._package_in_handle(private_key)
            # self._send_state("CLIENT_COMMANDS_RESULT_INGESTED")
            #
            # # 3. ASk for files:
            # while True:
            #     match self.socket.recv(1024).decode("utf_8"):
            #         case "SOL_FILE":
            #             raise SOL_Error("NO SOL_FILE Ingesting client side defined") # todo
            #
            #         case "SOL_STOP" | _:
            #             break
            #
            # # 4. CLEANUP
            # for f in package.file_list:  # type: SOL_File
            #     f.cleanup()
            #
            # # 4. Return Command list
            # return result

        # if anything goes wrong, it should be excepted here so the entire program doesn't crash
        except socket.timeout:
            raise SOL_Error(4103,"Connection became unavailable")
        except json.JSONDecodeError as e:
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")