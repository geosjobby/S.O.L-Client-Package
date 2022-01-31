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
    def __init__(self, username:str,password:str,password_new:str=None):
        self._username = username
        self._password = password
        self._password_new = password_new

    def dict(self) -> dict:
        return {
            "username":self._username,
            "password":self._password,
            "password_new":self._password_new
        }

    def to_json(self) -> str:
       return "!!!__SOL_CREDENTIALS__!!!"