# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import hashlib
import socket
import base64

# Custom Structure
from ._Base_Classes import SOL_Connector_Base, SOL_Error, SOL_Package_Base
from ._SOL_Connector_Ciphers import SOL_Connector_Ciphers

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector(SOL_Connector_Base):
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Define Sub Classes
        self.ciphers = SOL_Connector_Ciphers(self)

    def connection_setup(self, address:str, port:int):
        if isinstance(address, str) and isinstance(port, int):
            self.address = address
            self.port = port
        else:
            raise SOL_Error("Address and or port were not in the correct type")

    def send(self, package:SOL_Package_Base)->list[list]:
        # check the package is the correct format
        if not isinstance(package, SOL_Package_Base):
            return [[4101, None]]

        # Connect to API server and send data
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(10)

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # 1. Send request for public key
            self.socket.send("SOL_KEY".encode("utf_8"))
            match self.socket.recv(1024):
                case b"5555":  # API unavailable at the server level and will not be able to send a reply back
                    return [[5555, None]]
                case bytes(public_key_str):
                    public_key = self.ciphers.pp_import_key(public_key_str)
                case _:
                    raise SOL_Error

            # 2. Encrypt the package
            encrypted_package,session_key_encrypted,tag,nonce = self.ciphers.pp_encrypt(package.data(), public_key)
            package_param = b":".join([
                base64.b64encode(session_key_encrypted),
                base64.b64encode(tag),
                base64.b64encode(nonce),
                base64.b64encode(len(encrypted_package).to_bytes(len(encrypted_package).bit_length(), "big"))
            ])

            # 3. send message parameters
            self.socket.send(package_param)

            # 4. Send the entire package if we get the all clear
            if self.socket.recv(1024).decode("utf_8") != "SOL_CLEAR":
                raise SOL_Error
            self.socket.send(encrypted_package)

            # ----------------------------------------------------------------------------------------------------------
            # grab the reply package
            # ----------------------------------------------------------------------------------------------------------

            # 1. Receive request for public key:
            private_key, public_key = self.ciphers.pp_generate_keys()
            if self.socket.recv(1024).decode("utf_8") != "CLIENT_KEY":
                raise SOL_Error
            self.socket.sendall(public_key.exportKey())

            # 2. Receive the encrypted package's length
            session_key_encrypted, tag, nonce, package_length = (base64.b64decode(a) for a in self.socket.recv(1024*10).split(b":"))
            package_length = int.from_bytes(package_length,"big")
            if package_length <= 0:
                raise SOL_Error

            self.socket.sendall("CLIENT_CLEAR".encode("utf_8"))

            # 3. assemble the actual package data
            q_data_encrypted = b""
            while len(q_data_encrypted) < package_length:
                q_data_encrypted += self.socket.recv(2048)

            # 4. decrypt the package
            q_data = self.ciphers.pp_decrypt(q_data_encrypted, private_key,session_key_encrypted,tag,nonce)

            # form the reply list
            match json.loads(q_data.decode("utf_8")):
                case {"hash": {"r": rh}, "r": r} \
                    if isinstance(rh, str) \
                    and isinstance(r, list) \
                    and hashlib.sha256(json.dumps(r).encode("utf_8")).hexdigest() == rh:
                        return r
                case _:
                    raise SOL_Error

        # if anything goes wrong, it should be excepted so the entire program doesn't crash
        except SOL_Error or json.JSONDecodeError or socket.timeout:
            return [[4104, None]]