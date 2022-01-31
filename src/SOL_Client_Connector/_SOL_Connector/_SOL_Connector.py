# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import socket

# Custom Structure
from .._Base_Classes import SOL_Connector_Base, STOP_Error, SOL_Error, SOL_Package_Base
from ..SOL_Encryption import *
from .._SOL_File import SOL_File
from .._SOL_PackageHandlers import PackageHandler_Full as PH

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
    def __init__(self, address:str,port:int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.PH = PH(self.socket)

    def _buffer_size(self, object_size:int):
        # Set up address and port
        if not isinstance(address, str):
            raise SOL_Error(4401, "Address was not defined as a string")
        if not isinstance(port, int):
            raise SOL_Error(4401, "Port was not defined as an integer")
        self.address = address
        self.port = port

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
            # self.socket.settimeout(600) # 10 minute timeout
            self.socket.settimeout(6000) # 100 minute timeout

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # 1. Send request for public key
            self.PH.send_state("SOL_KEY")
            server_public_key = pp_import_key(
                self.PH.package_input("KEY", client_private_key)["key"]
            )

            # 2. Send API KEY
            self.PH.wait_for_state("API_KEY")
            self.PH.package_output_encrypted(
                state="API_KEY",
                package_dict={"api_key":package.api_key},
                server_public_key=server_public_key
            )

            # 3. Wait for API key to be validated
            match self.PH.wait_for_state_multiple(["API_KEY_OK"]):
                case "API_KEY_OK":
                    pass # Normal way of transaction and too lazy to keep indenting forwards
                case _:
                    return [[5000, None]]

            # 4. Send commands
            self.PH.wait_for_state("CLIENT_COMMANDS")
            self.PH.package_output_encrypted(
                state="CLIENT_COMMANDS",
                package_dict=package_dict,
                server_public_key=server_public_key
            )
            self.PH.wait_for_state("COMMANDS_LENCHECKED")

            # ----------------------------------------------------------------------------------------------------------
            # Send addition data
            # ----------------------------------------------------------------------------------------------------------
            # 5. Send files if present
            for f in package.file_list: #type: SOL_File
                self.PH.send_state("FILE_PRESENT")
                self.PH.wait_for_state("FILE_READY")
                self.PH.file_package_output(
                    state="FILE",
                    file_object=f,
                    server_public_key=server_public_key
                )

            # needed to let the API know to continue
            self.PH.send_state("CONTINUE")

            # ----------------------------------------------------------------------------------------------------------
            # Wait for parser to finish
            # ----------------------------------------------------------------------------------------------------------
            # 6. Wait for the API to respond

            # ----------------------------------------------------------------------------------------------------------
            # Receive reply package
            # ----------------------------------------------------------------------------------------------------------
            # 7. Send Client public key
            self.PH.wait_for_state("CLIENT_KEY")
            self.PH.package_output_plain(
                state="KEY",
                package_dict={"key": client_public_key.exportKey().decode("utf_8")}
            )

            # 8. Wait for reply package
            self.PH.send_state("SOL_REPLY")
            package_dict = self.PH.package_input(
                state="SOL_REPLY",
                client_private_key=client_private_key
            )
            # ----------------------------------------------------------------------------------------------------------
            # Receive addition data
            # ----------------------------------------------------------------------------------------------------------
            # 9. Ask for files to be sent
            while True:
                match self.PH.wait_for_state_multiple(["FILE_PRESENT","CONTINUE"]):
                    case "FILE_PRESENT":
                        self.PH.send_state("FILE_READY")
                        self.PH.file_package_input(
                            state="FILE",
                            client_private_key=client_private_key
                        )
                        continue # go to next iteration as there might be more files incoming

                    case "CONTINUE": # No more files were present
                        break

            # 10. Run a cleanup
            for f in package.file_list:  # type: SOL_File
                f.cleanup()

            # 11. Return package to the client, for further processing by client application
            return package_dict["commands"]

        # if anything goes wrong, it should be excepted here so the entire program doesn't crash
        except STOP_Error as e:
            return [[e.args[0],e.args[1]]]

        except socket.timeout:
            raise SOL_Error(4103,"Connection became unavailable")

        except json.JSONDecodeError as e:
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")