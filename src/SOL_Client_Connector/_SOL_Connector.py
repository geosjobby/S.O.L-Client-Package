# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import socket
import base64
import sys
import os
import functools

from Crypto.PublicKey.RSA import RsaKey

# Custom Structure
from ._Base_Classes import SOL_Connector_Base, _SOL_STOP_Error, SOL_Error, SOL_Package_Base
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
        self._cleanup()

    def _cleanup(self):
        self._client_public_key = None
        self._client_private_key = None
        self._server_public_key = None

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
            case "STOP":
                self._stop_handling()
            case "":
                raise SOL_Error(4103, f"Connection became unavailable")
            case a:
                raise SOL_Error(4103, f"Connection became unavailable, unexpected command: {a}")

    def _wait_for_state_multiple(self, states:list):
        state = self.socket.recv(1024).decode("utf_8")
        if state == "STOP":
            self._stop_handling()
        elif state not in states:
            raise self.error(4103)
        return state

    def _send_state(self, state: str):
        self.socket.send(state.encode("utf_8"))

    def _stop_handling(self):
        self._send_state("STOP_DATA")
        stop_dict = self.package_in_plain_and_encrypted("STOP_DATA")
        error_code = list(stop_dict.keys())[0]
        error_data = list(stop_dict.values())[0]
        raise _SOL_STOP_Error(error_code,error_data)


        # ------------------------------------------------------------------------------------------------------------------
    # - Form Package and parameters -
    # ------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def package_parameters(session_key_encrypted: bytes = None, tag: bytes = None, nonce: bytes = None,package_length: int = None) -> bytes:
        return json.dumps({
            "sske": base64.b64encode(session_key_encrypted).decode("utf8") if session_key_encrypted is not None else None,
            "tag": base64.b64encode(tag).decode("utf8") if tag is not None else None,
            "nonce": base64.b64encode(nonce).decode("utf8") if nonce is not None else None,
            "len": package_length if package_length is not None else None,
        }).encode("utf8")

    @staticmethod
    def file_package_parameters(session_key_encrypted: bytes = None, tag: bytes = None, nonce: bytes = None,package_length: int = None, filename:str=None,hash_value:str=None) -> bytes:
        return json.dumps({
            "sske": base64.b64encode(session_key_encrypted).decode("utf8") if session_key_encrypted is not None else None,
            "tag": base64.b64encode(tag).decode("utf8") if tag is not None else None,
            "nonce": base64.b64encode(nonce).decode("utf8") if nonce is not None else None,
            "len": package_length if package_length is not None else None,
            "file_name": base64.b64encode(filename.encode("utf8")).decode("utf8") if filename is not None else None,
            "hash_value": base64.b64encode(hash_value.encode("utf8")).decode("utf8") if hash_value is not None else None,
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
        package_parameters = self.package_parameters(None, None, None, sys.getsizeof(package_data))
        # send the data
        self._package_out(state, package_parameters, package_data)

    def package_out_encrypted(self, state: str, package_dict: dict) -> None:
        # assemble the package bytes
        package_data = self.package_data(package_dict)
        # Encrypt package
        encrypted_package, session_key_encrypted, tag, nonce = pp_encrypt(
            package_data,
            self._server_public_key
        )
        # assemble package parameters
        package_parameters = self.package_parameters(session_key_encrypted, tag, nonce, sys.getsizeof(encrypted_package))
        # send the data
        self._package_out(state, package_parameters, encrypted_package)

    # ------------------------------------------------------------------------------------------------------------------
    # - FILE Packages outgoing -
    # ------------------------------------------------------------------------------------------------------------------
    def file_package_out_encrypted(self, state: str, file_object: SOL_File) -> None:
        # Encrypt File
        with open(f"temp/{file_object.filename_temp}", "rb") as file_temp, open(f"temp/{file_object.filename_transmission}", "ab+") as file_transmission:
            encrypted_file, session_key_encrypted, tag, nonce = pp_encrypt(
                file_temp.read(),
                self._server_public_key
            )
            file_transmission.write(encrypted_file)
        # assemble package parameters
        package_length = os.path.getsize(f"temp/{file_object.filename_transmission}")

        package_parameters = self.file_package_parameters(
            session_key_encrypted,
            tag,
            nonce,
            package_length,
            file_object.filename_transmission,
            file_object.hash_value
        )

        # Send parameters
        self._send_state(f"{state}_PARAM")
        self._wait_for_state(f"{state}_PARAM_READY")
        self.socket.sendall(package_parameters)
        self._wait_for_state(f"{state}_PARAM_INGESTED")

        # get the buffer size
        match package_length:
            case int(a) if a < 1048576:  # up to 1mb
                buffer_size = 102400  # buffer of 100kb
            case int(a) if 1048576 < a < 10485760:  # between 1mb and 10mb
                buffer_size = 1048576  # buffer of 1mb
            case int(a) if 10485760 < a < 10485760:  # between 10mb and 100mb
                buffer_size = 10485760  # buffer of 10mb
            case int(a) if a > 10485760:
                buffer_size = 10485600  # buffer of 100mb
            case _:
                raise self.error(5000)

        # send the file in chunks
        with open(f"temp/{file_object.filename_transmission}", "rb") as file_transmission_:
            for chunk in iter(functools.partial(file_transmission_.read, buffer_size), b""):
                self.socket.sendall(chunk)

        # wait for ingestion to finish
        self._wait_for_state(f"{state}_PACKAGE_INGESTED")

        # wait for file decompression and check to happen
        self._wait_for_state(f"{state}_CHECKED")

        # Cleanup the temp files
        os.remove(f"temp/{file_object.filename_transmission}")
        os.remove(f"temp/{file_object.filename_temp}")

    # ------------------------------------------------------------------------------------------------------------------
    # - Default Packages incoming -
    # ------------------------------------------------------------------------------------------------------------------
    def package_in_plain_and_encrypted(self, state: str) -> dict:
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
                    self._client_private_key,
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
            self._client_private_key, self._client_public_key = pp_generate_keys()

            # Connect to API server and send data
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(6000) # 1 minute timeout

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # 1. Send request for public key
            self._send_state("SOL_KEY")
            key_dict = self.package_in_plain_and_encrypted("KEY")
            self._server_public_key = pp_import_key(key_dict["key"])

            # 2. Send API KEY
            self._wait_for_state("API_KEY")
            self.package_out_encrypted(
                state="API_KEY",
                package_dict={"api_key":package.api_key}
            )

            # 3. Wait for API key to be validated
            match self._wait_for_state_multiple(["API_KEY_OK"]):
                case "API_KEY_OK":
                    pass # Normal way of transaction and too lazy to keep indenting forwards
                case _:
                    return [[5000, None]]

            # 4. Send commands
            self._wait_for_state("CLIENT_COMMANDS")
            self.package_out_encrypted(
                state="CLIENT_COMMANDS",
                package_dict=package_dict
            )
            self._wait_for_state("COMMANDS_LENCHECKED")

            # ----------------------------------------------------------------------------------------------------------
            # Send addition data
            # ----------------------------------------------------------------------------------------------------------
            # 5. Send files if present
            for f in package.file_list: #type: SOL_File
                self._send_state("FILE_PRESENT")
                match self._wait_for_state_multiple(["FILE_READY"]):
                    case "FILE_READY":
                        self.file_package_out_encrypted("FILE",f)

            # needed to let the API know to continue
            self._send_state("CONTINUE")

            # ----------------------------------------------------------------------------------------------------------
            # Wait for parser to finish
            # ----------------------------------------------------------------------------------------------------------
            # 6. Wait for the API to respond


            # ----------------------------------------------------------------------------------------------------------
            # Receive reply package
            # ----------------------------------------------------------------------------------------------------------
            # 7. Send Client public key
            self._wait_for_state("CLIENT_KEY")
            self.package_out_plain(
                state="KEY",
                package_dict={"key": self._client_public_key.exportKey().decode("utf_8")}
            )

            # 8. Wait for reply package
            self._send_state("SOL_REPLY")
            package_dict = self.package_in_plain_and_encrypted(
                state="SOL_REPLY"
            )
            # ----------------------------------------------------------------------------------------------------------
            # Receive addition data
            # ----------------------------------------------------------------------------------------------------------
            # 9. Ask for files to be sent
            while True:
                match self._wait_for_state_multiple(["FILE_PRESENT","CONTINUE"]):
                    case "FILE_PRESENT":
                        self._send_state("FILE_READY")
                        file_package_dict = self.package_in_plain_and_encrypted(
                            state="FILE"
                        )
                        continue # go to next iteration as there might be more files incoming

                    case "CONTINUE": # No more files were present
                        break

            # 10. Return package to the client, for further processing by client application
            self._cleanup()
            return package_dict["commands"]

        # if anything goes wrong, it should be excepted here so the entire program doesn't crash
        except _SOL_STOP_Error as e:
            self._cleanup()
            return [[e.args[0],e.args[1]]]

        except socket.timeout:
            self._cleanup()
            raise SOL_Error(4103,"Connection became unavailable")

        except json.JSONDecodeError as e:
            self._cleanup()
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")