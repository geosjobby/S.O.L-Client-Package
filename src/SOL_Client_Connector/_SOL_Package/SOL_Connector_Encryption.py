# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
from Crypto.Random import get_random_bytes, new
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import AES, PKCS1_OAEP

# Custom Packages

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
def pp_import_key(public_key_str:bytes) -> RsaKey:
    """Import an RSA key from string"""
    return RSA.importKey(public_key_str)

def pp_generate_keys() -> tuple[RsaKey,RsaKey]:
    """Generates a pair of public and private keys"""
    m_length = 1024 # todo change this to 2048 in production
    private_key = RSA.generate(m_length, new().read)
    public_key = private_key.public_key()
    return private_key, public_key

def pp_encrypt(message: bytes, public_key:RsaKey) -> tuple[bytes,bytes,bytes,bytes]:
    """Encrypts the message with the given public key"""
    # Set Encryptor and variables
    session_key = get_random_bytes(16)
    session_key_encrypted = PKCS1_OAEP.new(public_key).encrypt(session_key)

    # Actually Encode the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    encrypted_package, tag = cipher_aes.encrypt_and_digest(message)

    return encrypted_package,session_key_encrypted,tag, cipher_aes.nonce

def pp_decrypt(package_encrypted: bytes, private_key:RsaKey, session_key_encrypted:bytes, tag:bytes, nonce:bytes):
    """Decrypts the given package with the session key, which in turn is decrypted by the private key"""
    # Set decryptor and variables
    cipher_aes = AES.new(
        PKCS1_OAEP.new(private_key).decrypt(session_key_encrypted), # session key
        AES.MODE_EAX,
        nonce
    )
    return cipher_aes.decrypt_and_verify(package_encrypted, tag)


def pp_cipher_ingest():
    pass

def pp_cipher_create(public_key):
    """Encrypts the message with the given public key"""
    # Set Encryptor and variables
    session_key = get_random_bytes(16)
    session_key_encrypted = PKCS1_OAEP.new(public_key).encrypt(session_key)

    # Actually Encode the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    return session_key_encrypted, cipher_aes.nonce, cipher_aes