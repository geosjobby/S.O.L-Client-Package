# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import hashlib
import socket
import asyncio

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

    def connection_setup(self, address:str, port:int) -> bool:
        self.address = address if isinstance(address, str) else False
        self.port = port if isinstance(port, int) else False
        return True if self.port and self.address else False

    async def send(self, package:SOL_Package_Base)->list[list]:
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
            match self.socket.recv(1024).decode("utf_8"):
                case "5555":  # API unavailable at the server level and will not be able to send a reply back
                    return [[5555, None]]
                case str(public_key_str):
                    public_key = self.ciphers.pp_import_key(public_key_str)
                case _:
                    raise SOL_Error

            # 2. Encrypt the package
            package_encrypted = b"".join(await self.ciphers.pp_encrypt(package.data(), public_key))

            # 3. Send the length package so the server knows what to expect
            self.socket.send(len(package_encrypted).to_bytes(len(package_encrypted).bit_length(), "big"))

            # 4. Send the entire package if we get the all clear
            if self.socket.recv(1024).decode("utf_8") != "SOL_CLEAR":
                raise SOL_Error
            self.socket.send(package_encrypted)

            # ----------------------------------------------------------------------------------------------------------
            # grab the reply package
            # ----------------------------------------------------------------------------------------------------------

            # 1. Receive request for public key:
            private_key, public_key = self.ciphers.pp_generate_keys()
            if self.socket.recv(1024).decode("utf_8") != "CLIENT_KEY":
                raise SOL_Error
            self.socket.sendall(public_key.exportKey())

            # 2. Receive the encrypted package's length
            match int.from_bytes(self.socket.recv(1024),"big"):
                case package_length if package_length > 0:
                    self.socket.sendall("CLIENT_CLEAR".encode("utf_8"))
                case _:
                    raise SOL_Error

            # 3. assemble the actual package data
            q_data_encrypted = b""
            while len(q_data_encrypted) < package_length:
                q_data_encrypted += self.socket.recv(2048)

            # 4. decrypt the package
            q_data = await self.ciphers.pp_decrypt(q_data_encrypted, private_key)

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