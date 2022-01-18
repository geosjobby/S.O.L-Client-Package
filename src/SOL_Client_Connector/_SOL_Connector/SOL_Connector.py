# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Structure
import json
import hashlib
import socket
import asyncio

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# PySide Structure

# Custom Structure

# Custom GUI Structure

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector:
    address:str
    port:int
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def pp_generate_keys(self) -> tuple:
        m_length = 1024
        private_key = RSA.generate(m_length, Random.new().read)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    async def pp_encrypt_partial(message_chunk, encryptor):
        return base64.b64encode(encryptor.encrypt(message_chunk))

    async def pp_encrypt(self, message: bytes, public_key) -> list:
        # Set Encryptor and variables
        encryptor = PKCS1_OAEP.new(public_key)
        n = int(public_key.size_in_bytes() / 2)

        # Actually Encode
        result = await asyncio.gather(*[
            self.pp_encrypt_partial(message[i:i + n], encryptor) for i in range(
                0,
                len(message),
                n
            )
        ])

        return [str(len(result[0])).encode('utf_8'), b";", *result]

    @staticmethod
    async def pp_decrypt_partial(message_chunk, decryptor):
        return decryptor.decrypt(base64.b64decode(message_chunk))

    async def pp_decrypt(self, message_encoded_encrypted: bytes, private_key):
        # Set decryptor and variables
        decryptor = PKCS1_OAEP.new(private_key)
        a = message_encoded_encrypted.find(b";")
        len_p = int(message_encoded_encrypted[:a])
        j1 = a + 1
        j2 = len_p + (a + 1)

        # Actually Decode and Crypt
        result = await asyncio.gather(*[
            self.pp_decrypt_partial(message_encoded_encrypted[j1 + i:i + j2], decryptor) for i in range(
                0,
                len(message_encoded_encrypted[a + 1:]),
                len_p
            )
        ])
        # del decryptor, message_encoded_encrypted,a, len_p, j1,j2
        return b"".join(result)

    def connection_param(self, address:str, port:int):
        self.address = address if isinstance(address, str) else False
        self.port = port if isinstance(port, int) else False
        if all([self.port, self.address]):
            return True
        else:
            # if the param were set incorrectly in any way
            raise ValueError

    async def send(self, api_key:str=None, q_list:list[dict]=None, credentials:dict=None)->list[list]:
        # check the api_key and q_list for the correct format
        if api_key is None:
            api_key = ""
        elif not isinstance(api_key, str):
               return [[4101, None]]
        if q_list is not None and not isinstance(q_list, list) and all(isinstance(i, dict) for i in q_list):
                return [[4102, None]]

        # Connect to API server and send data
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.connect((self.address, self.port))
            self.socket.settimeout(10)

            # ----------------------------------------------------------------------------------------------------------
            # send package so the server
            # ----------------------------------------------------------------------------------------------------------
            # assemble the package as a json string in bytes
            if api_key is not None and q_list is not None:
                package = json.dumps({
                    "api_key": api_key,
                    "hash": {
                        "q": hashlib.sha256(json.dumps(q_list).encode("utf_8")).hexdigest(),
                        "api_key": hashlib.sha256(api_key.encode("utf_8")).hexdigest()
                    },
                    "q": q_list
                }).encode("utf_8")

            elif credentials is not None:
                package = json.dumps({
                    "credentials": credentials
                }).encode("utf_8")

            # 1. Send request for public key
            self.socket.send("SOL_KEY".encode("utf_8"))
            match self.socket.recv(1024).decode("utf_8"):
                case "5555;None":  # API unavailable at the server level and will not be able to send a reply back
                    return [[5555, None]]
                case str(a):
                    public_key_str = a
                case _:
                    raise ConnectionError

            # 2. Encrypt the package
            public_key = RSA.importKey(public_key_str.encode("utf_8"))
            package_encrypted = b"".join(await self.pp_encrypt(package,public_key))

            # 3. Send the length package so the server knows what to expect
            self.socket.send(len(package_encrypted).to_bytes(len(package_encrypted).bit_length(), "big"))

            # 4. Send the entire package if we get the all clear
            if  self.socket.recv(1024).decode("utf_8") != "SOL_CLEAR":
                raise ConnectionError
            self.socket.send(package_encrypted)

            del public_key

            # ----------------------------------------------------------------------------------------------------------
            # grab the reply package
            # ----------------------------------------------------------------------------------------------------------

            # 1. Receive request for public key:
            private_key, public_key = self.pp_generate_keys()
            if self.socket.recv(1024).decode("utf_8") != "CLIENT_KEY":
                raise ConnectionError
            self.socket.sendall(public_key.exportKey())

            # 2. Receive the encrypted package's length
            match int.from_bytes(self.socket.recv(1024),"big"):
                case package_length if package_length > 0:
                    self.socket.sendall("CLIENT_CLEAR".encode("utf_8"))
                case _:
                    raise ConnectionError

            # 3. assemble the actual package data
            q_data_encrypted = b""
            while len(q_data_encrypted) < package_length:
                q_data_encrypted += self.socket.recv(2048)

            # 4. decrypt the package
            q_data = await self.pp_decrypt(q_data_encrypted, private_key)

            # form the reply list
            match json.loads(q_data.decode("utf_8")):
                case {"hash": {"r": rh}, "r": r} \
                    if isinstance(rh, str) \
                    and isinstance(r, list) \
                    and hashlib.sha256(json.dumps(r).encode("utf_8")).hexdigest() == rh:
                        return r
                case _:
                    raise ConnectionError

        # if anything goes wrong, it should be excepted so the entire program doesn't crash
        except ConnectionError or json.JSONDecodeError or socket.timeout:
            return [[4103, None]]