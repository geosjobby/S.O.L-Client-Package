# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import keyring
import bcrypt
from Crypto.Random import get_random_bytes, new
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import AES, PKCS1_OAEP

# Custom Packages

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------------
# - Keyring methods
# ------------------------------------------------------------------------------------------------------------------
def kr_set(self, app: str, name: str, password: str) -> bool:
    if not isinstance(app, str) or not isinstance(name, str) or isinstance(password, str):
        return False
    else:
        keyring.set_password(app, name, password)
        return True


def kr_get(self, app: str, name: str) -> tuple[True, str] | tuple[False, None]:
    if not isinstance(app, str) or not isinstance(name, str):
        return False, None
    else:
        return True, keyring.get_password(app, name)


# ------------------------------------------------------------------------------------------------------------------
# - Bcrypt methods -
# ------------------------------------------------------------------------------------------------------------------
def b_set(password: str) -> tuple[True, bytes] or tuple[False, None]:
    if not isinstance(password, str):
        return False, None
    else:
        return True, bcrypt.hashpw(password.encode("utf_8"), bcrypt.gensalt())


def b_validate(password, hashed_password) -> bool:
    return bcrypt.checkpw(password, hashed_password)


# ------------------------------------------------------------------------------------------------------------------
# - Public/Private key methods -
# ------------------------------------------------------------------------------------------------------------------
def pp_generate_keys() -> tuple[RsaKey, RsaKey]:
    m_length = 1024  # todo change this to 2048 in production
    private_key = RSA.generate(m_length, new().read)
    public_key = private_key.public_key()
    return private_key, public_key

def pp_import_key(public_key_str: bytes) -> RsaKey:
    return RSA.importKey(public_key_str)

def pp_encrypt(message: bytes, public_key) -> tuple[bytes, bytes, bytes, bytes]:
    # Set Encryptor and variables
    encryptor = PKCS1_OAEP.new(public_key)
    session_key = get_random_bytes(16)
    session_key_encrypted = encryptor.encrypt(session_key)

    # Actually Encode the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    encrypted_package, tag = cipher_aes.encrypt_and_digest(message)

    return encrypted_package, session_key_encrypted, tag, cipher_aes.nonce

def pp_decrypt(package_encrypted: bytes, private_key, session_key_encrypted, tag, nonce) -> bytes:
    # Set decryptor and variables
    decryptor = PKCS1_OAEP.new(private_key)
    session_key = decryptor.decrypt(session_key_encrypted)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(package_encrypted, tag)

def pp_cipher_aes_encryptor(public_key) -> tuple[bytes, bytes, AES]:
    """Encrypts the message with the given public key"""
    # Set Encryptor and variables
    session_key = get_random_bytes(16)
    session_key_encrypted = PKCS1_OAEP.new(public_key).encrypt(session_key)

    # Actually Encode the message
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    return session_key_encrypted, cipher_aes.nonce, cipher_aes

def pp_cipher_aes_decryptor(private_key, session_key_encrypted, nonce) -> AES:
    # Set decryptor and variables
    decryptor = PKCS1_OAEP.new(private_key)
    session_key = decryptor.decrypt(session_key_encrypted)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return cipher_aes