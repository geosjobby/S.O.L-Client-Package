# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
from Crypto.Random import get_random_bytes, new
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import AES, PKCS1_OAEP

# Custom Packages
from .._Base_Classes import SOL_Connector_Ciphers_Base, SOL_Connector_Base

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Connector_Ciphers(SOL_Connector_Ciphers_Base):
    def __init__(self, connector:SOL_Connector_Base):
        self._c = connector

    def pp_import_key(self, public_key_str:bytes) -> RsaKey:
        return RSA.importKey(public_key_str)

    def pp_generate_keys(self) -> tuple[RsaKey,RsaKey]:
        m_length = 1024
        private_key = RSA.generate(m_length, new().read)
        public_key = private_key.public_key()
        return private_key, public_key

    def pp_encrypt(self, message: bytes, public_key:RsaKey) -> tuple[bytes,bytes,bytes,bytes]:
        # Set Encryptor and variables
        encryptor = PKCS1_OAEP.new(public_key)
        session_key = get_random_bytes(16)
        session_key_encrypted = encryptor.encrypt(session_key)

        # Actually Encode the message
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        encrypted_package, tag = cipher_aes.encrypt_and_digest(message)

        return encrypted_package,session_key_encrypted,tag, cipher_aes.nonce

    def pp_decrypt(self, package_encrypted: bytes, private_key, session_key_encrypted, tag, nonce):
        # Set decryptor and variables
        decryptor = PKCS1_OAEP.new(private_key)
        session_key = decryptor.decrypt(session_key_encrypted)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        return cipher_aes.decrypt_and_verify(package_encrypted, tag)