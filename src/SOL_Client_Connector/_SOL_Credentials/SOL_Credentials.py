# ----------------------------------------------------------------------------------------------------------------------
# - Package Imports -
# ----------------------------------------------------------------------------------------------------------------------
# General Packages
import base64
import json

# Custom Packages
from .._Base_Classes import BASE_SOL_Credentials
from ..SOL_Encryption import pp_encrypt

# ----------------------------------------------------------------------------------------------------------------------
# - Code -
# ----------------------------------------------------------------------------------------------------------------------
class SOL_Credentials(BASE_SOL_Credentials):
    def __init__(self, username:str,password:str,password_new:str=""):
        self._username = username.encode("utf_8")
        self._password = password.encode("utf_8")
        self._password_new = password_new.encode("utf_8")

    def encrypt(self, server_public_key) -> dict:
        self._encrypted_credentials, self._session_key, self._tag, self._nonce = pp_encrypt(
            b";".join([self._username, self._password, self._password_new]),
            server_public_key
        )
        return {
           "ec":    base64.b64encode(self._encrypted_credentials).decode("utf_8"),
           "key":   base64.b64encode(self._session_key).decode("utf_8"),
           "tag":   base64.b64encode(self._tag).decode("utf_8"),
           "nonce": base64.b64encode(self._nonce).decode("utf_8")
       }

    def to_json(self) -> str:
       return "!!!__SOL_CREDENTIALS__!!!"