# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import socket

# Custom Structure
from .._Base_Classes import SOL_Connector_Base, STOP_Error, SOL_Error, SOL_Package_Base, BASE_SOL_Credentials
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
        # --------------------------------------------------------------------------------------------------------------
        # Prepare the package and some more stuff
        # --------------------------------------------------------------------------------------------------------------
        try:
            # check the package is the correct format
            if not isinstance(package, SOL_Package_Base):
                raise SOL_Error(4402, "Package was not defined as a SOL_Package Object")

            # Run the pre-check (this does the compression)
            package.pre_check()
            package_dict = package.dict()
            client_private_key, client_public_key = pp_generate_keys()
            client_public_key_exported = client_public_key.exportKey().decode("utf_8")

            # Connect to API server and send data
            self.socket.connect((self.address, self.port))
            # self.socket.settimeout(600) # 10 minute timeout
            self.socket.settimeout(6000) # 100 minute timeout

        except json.JSONDecodeError as e:
            raise SOL_Error(4404, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")

        # except ConnectionRefusedError:
        #     raise SOL_Error(5005)

        # --------------------------------------------------------------------------------------------------------------
        # send package so the server
        # --------------------------------------------------------------------------------------------------------------
        with self.socket:
            try:
                while True:
                    match self.PH.wait_for_state_undefined():
                        # ----------------------------------------------------------------------------------------------
                        # data states
                        # ----------------------------------------------------------------------------------------------
                        case "SOL_KEY":
                            server_public_key = pp_import_key(
                                self.PH.package_input("SOL_KEY", client_private_key)["key"]
                            )

                        case "API_KEY" if server_public_key is not None:
                            self.PH.package_output_encrypted(
                                state="API_KEY",
                                package_dict={"api_key": package.api_key},
                                server_public_key=server_public_key
                            )

                        case "COMMANDS" if server_public_key is not None:
                            self.PH.package_output_encrypted(
                                state="COMMANDS",
                                package_dict=package_dict,
                                server_public_key=server_public_key
                            )

                        case "CLIENT_KEY" if server_public_key is not None:
                            self.PH.package_output_encrypted(
                                state="CLIENT_KEY",
                                package_dict={"key": client_public_key_exported},
                                server_public_key=server_public_key
                            )

                        case "REPLY":
                            package_dict = self.PH.package_input(
                                state="REPLY",
                                client_private_key=client_private_key
                            )

                        case "ADDITIONAL":
                            for f in package.file_list:  # type: SOL_File
                                self.PH.send_state("FILE")
                                self.PH.wait_for_state("FILE")
                                self.PH.file_package_output(
                                    state="FILE",
                                    file_object=f,
                                    server_public_key=server_public_key
                                )
                            if package.credentials is not None:
                                self.PH.send_state("CREDENTIALS")
                                self.PH.wait_for_state("CREDENTIALS")
                                self.PH.package_output_encrypted(
                                    state="CREDENTIALS",
                                    package_dict=package.credentials.dict(),
                                    server_public_key=server_public_key
                                )
                                # needed to let the API know to continue
                            self.PH.send_state("END")

                        # ----------------------------------------------------------------------------------------------
                        # flow states
                        # ----------------------------------------------------------------------------------------------

                        case "INFO":
                            package_dict = self.PH.package_input(
                                state="INFO",
                                client_private_key=client_private_key
                            )
                            #todo add something here to do something with the info, QSignal
                            print(package_dict)
                            continue

                        case "END":
                            # natural end to a conversation
                            break

                        case "STOP":
                            stop_data = self.PH.package_input(
                                state="STOP",
                                client_private_key=client_private_key
                            )
                            return stop_data["stop"]

                        case a:
                            raise SOL_Error(a)

                # 11. Run a cleanup
                for f in package.file_list:  # type: SOL_File
                    f.cleanup()

                # 12. Return package to the client, for further processing by client application
                return package_dict["reply"]

            except (socket.timeout, ConnectionAbortedError, ConnectionResetError):
                raise SOL_Error(4403,"Connection became unavailable")