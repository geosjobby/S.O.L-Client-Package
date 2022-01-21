# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import asyncio

# Custom Packages
from .._Base_Classes import SOL_Connector_Ciphers_Base, SOL_Connector_Base

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector_Ciphers(SOL_Connector_Ciphers_Base):
    def __init__(self, connector:SOL_Connector_Base):
        self._c = connector

    def pp_import_key(self, public_key_str:str):
        return RSA.importKey(public_key_str.encode("utf_8"))

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