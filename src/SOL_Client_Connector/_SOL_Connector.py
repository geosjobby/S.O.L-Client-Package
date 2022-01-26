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
from ._SOL_Connector_Ciphers import SOL_Connector_Ciphers

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

        # Define Sub Classes
        self.ciphers = SOL_Connector_Ciphers(self)

    def connection_setup(self, address:str, port:int):
        if isinstance(address, str):
            self.address = address
        else:
            raise SOL_Error(4401, "Address was not defined as a string")
        if isinstance(port, int):
            self.port = port
        else:
            raise SOL_Error(4401, "Port was not defined as an integer")

    def _package_out_handle(self, public_key: RsaKey, package_data:bytes, package_size:int=None):
        # 1. Encrypt the package
        encrypted_package, session_key_encrypted, tag, nonce = self.ciphers.pp_encrypt(package_data, public_key)
        package_param = b":".join([
            base64.b64encode(session_key_encrypted),
            base64.b64encode(tag),
            base64.b64encode(nonce),
            base64.b64encode(
                str(sys.getsizeof(encrypted_package)).encode("utf_8")
                if package_size is None
                    else str(package_size).encode("utf_8"))
        ])

        # 4. send message parameters
        self.socket.sendall(package_param)

        # 3. Send the entire package if we get the all clear
        if self.socket.recv(1024).decode("utf_8") != "SOL_CLEAR":
            raise SOL_Error(4103, "Connection became unavailable")

        self.socket.sendall(encrypted_package)

    def send(self, package:SOL_Package_Base)->list[list]:
        # check the package is the correct format
        if not isinstance(package, SOL_Package_Base):
            raise SOL_Error(4101,"Package was not defined as a SOL_Package Object")

        package_data = package.data()
        filepath_list = package.files() #type:list
        filepath_len = len(filepath_list)

        print(filepath_list, filepath_len)

        # Connect to API server and send data
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(60000)

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # 1. Send request for public key
            self.socket.send("SOL_KEY".encode("utf_8"))
            match self.socket.recv(1024):
                case b"5555":  # API unavailable at the server level and will not be able to send a reply back
                    raise SOL_Error(5555, "API server is unavailable, at the server level.\nIt did connect to the correct server location, but the actual API Server has crashed")
                case bytes(public_key_str):
                    public_key = self.ciphers.pp_import_key(public_key_str)
                case _:
                    raise SOL_Error(4104, "No connection could be established to the server")

            # 2. Send actual package
            self._package_out_handle(public_key, package_data)

            # 3. Check if files need to be sent
            if self.socket.recv(1024).decode("utf_8") != "SOL_FILES_PARAM":
                raise SOL_Error(4103, "Connection became unavailable")
            if filepath_len == 0:
                self.socket.send("CLIENT_STOP".encode("utf_8"))
            else:
                self.socket.send("CLIENT_FILES".encode("utf_8"))

                filepath_dict_package = json.dumps(filepath_list).encode("utf_8")
                self._package_out_handle(public_key, filepath_dict_package)

                for f in filepath_list:
                    with open(f"temp/{f}", "rb") as file:
                        file_size = os.path.getsize(f"temp/{f}")
                        self._package_out_handle(public_key, file.read(),package_size=file_size)

            # ----------------------------------------------------------------------------------------------------------
            # grab the reply package
            # ----------------------------------------------------------------------------------------------------------

            # 1. Receive request for public key:
            private_key, public_key = self.ciphers.pp_generate_keys()
            if self.socket.recv(1024).decode("utf_8") != "CLIENT_KEY":
                raise SOL_Error(4103,"Connection became unavailable")
            self.socket.sendall(public_key.exportKey())

            # 2. Receive the encrypted package's length
            session_key_encrypted, tag, nonce, package_length = (base64.b64decode(a) for a in self.socket.recv(1024).split(b":"))
            package_length = int.from_bytes(package_length,"big")
            if package_length <= 0:
                raise SOL_Error(4103,"Connection became unavailable")

            self.socket.sendall("CLIENT_CLEAR".encode("utf_8"))

            # 3. assemble the actual package data
            q_data_encrypted = b""
            while len(q_data_encrypted) < package_length:
                q_data_encrypted += self.socket.recv(2048)
                #todo Pyside Signal for download progress

            # 4. decrypt the package
            q_data = self.ciphers.pp_decrypt(q_data_encrypted, private_key,session_key_encrypted,tag,nonce)

            # form the reply list
            result_list = json.loads(q_data.decode("utf_8"))["r"]
            return result_list

        # if anything goes wrong, it should be excepted so the entire program doesn't crash
        except socket.timeout:
            raise SOL_Error(4103,"Connection became unavailable")
        except json.JSONDecodeError as e:
            raise SOL_Error(4102, f"Package could not be JSON Decoded,\nwith the following JSON decode error:\n{e}")